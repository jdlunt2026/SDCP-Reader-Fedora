/*
 * Realtek match-on-chip fingerprint reader driver with SDCP
 * (USB 2c0a:5816, "Realtek USB2.0 Finger Print Bridge" / "Secure BIO Sensor")
 *
 * This variant of the Realtek 5816 sensor ships with Windows Hello Enhanced
 * Sign-in Security firmware: it refuses to store a template unless the
 * enrollment ID is bound to a Secure Device Connection Protocol (SDCP)
 * session. The command set is the one used by the plain Realtek driver, plus
 * the SDCP messages, reverse engineered from a USB capture of the Windows
 * driver:
 *
 *   85 01 / 45 02   SDCP ConnectRequest / ConnectResponse
 *   85 03 / 45 04   SDCP Reconnect
 *   85 0b / 45 0c   identify nonce / identify result (id + MAC)
 *   45 09           enrollment nonce
 *   85 0a           enrollment commit (id || 00 || ff*16)
 *
 * The enrollment nonce is only issued right after an identify that found no
 * match, so enrollment starts with one identify touch, exactly like Windows.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define FP_COMPONENT "realtek_sdcp"

#include "drivers_api.h"
#include "fpi-sdcp.h"
#include "fpi-sdcp-claim.h"

#define EP_IN                   (2 | FPI_USB_ENDPOINT_IN)
#define EP_OUT                  (1 | FPI_USB_ENDPOINT_OUT)
#define EP_IN_BUF_SIZE          2048

#define CMD_LEN                 12
#define STATUS_LEN              5
#define CMD_TIMEOUT             1000
#define DATA_TIMEOUT            5000
#define STATUS_TIMEOUT          2000
#define POLL_INTERVAL           50

#define SLOT_LEN                52     /* valid, ?, subfactor, SHA256(id), 00, ff*16 */
#define SLOT_HASH_OFFSET        3
#define CONNECT_RESPONSE_LEN    0x4b6
#define IDENTIFY_RESULT_LEN     0x4a
#define DUP_CHECK_LEN           0x22
#define ACCEPT_SAMPLE_LEN       9
#define CAPTURE_POLL_LEN        5

#define ENROLL_SAMPLES          12     /* what the Windows driver collects */
#define SUBFACTOR               0xf5   /* WINBIO_FINGER_UNSPECIFIED_POS_01 */

#define PURPOSE_IDENTIFY        0x02
#define PURPOSE_ENROLL          0x04

#define IN_STATUS_SUCCESS       0x00
#define IN_STATUS_CMD_ERR       0x0c

struct _FpiDeviceRealtekSdcp
{
  FpSdcpDevice parent;

  FpiSsm      *task_ssm;
  GBytes      *resp;                 /* data phase of the last command */
  guint8       status[STATUS_LEN];   /* status phase of the last command */

  guint        slots;
  gint         enroll_stage;
  GBytes      *enroll_nonce;
  GBytes      *identify_id;
  GBytes      *identify_mac;
  GError      *retry_error;
  guint8       capture_purpose;
  gboolean     cancelled;
  gint         delete_slot;
};

G_DECLARE_FINAL_TYPE (FpiDeviceRealtekSdcp, fpi_device_realtek_sdcp, FPI,
                      DEVICE_REALTEK_SDCP, FpSdcpDevice)
G_DEFINE_TYPE (FpiDeviceRealtekSdcp, fpi_device_realtek_sdcp, FP_TYPE_SDCP_DEVICE)

static const FpIdEntry id_table[] = {
  { .vid = 0x2c0a,  .pid = 0x5816,  },
  { .vid = 0,  .pid = 0,  .driver_data = 0 },   /* terminating entry */
};

/******************************************************************************
 * Command transport
 *
 * Every command is a 12 byte header on EP_OUT, an optional data phase (write
 * on EP_OUT or read on EP_IN, depending on bits 7..6 of the first byte) and a
 * 5 byte status on EP_IN. Commands run as a sub-state machine; the data phase
 * ends up in self->resp and the status in self->status.
 */

enum {
  CMD_SEND,
  CMD_WRITE,
  CMD_READ,
  CMD_STATUS,
  CMD_NUM_STATES,
};

typedef struct
{
  guint8   header[CMD_LEN];
  GBytes  *write_data;
  gsize    read_len;
  gboolean check_status;
} RtkCmd;

static void
rtk_cmd_free (RtkCmd *cmd)
{
  g_clear_pointer (&cmd->write_data, g_bytes_unref);
  g_free (cmd);
}

static void
rtk_cmd_read_cb (FpiUsbTransfer *transfer,
                 FpDevice       *dev,
                 gpointer        user_data,
                 GError         *error)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  RtkCmd *cmd = fpi_ssm_get_data (transfer->ssm);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  /* The device sends zero length packets between phases; skip them */
  if (transfer->actual_length == 0)
    {
      fpi_ssm_jump_to_state (transfer->ssm, CMD_READ);
      return;
    }

  g_clear_pointer (&self->resp, g_bytes_unref);
  self->resp = g_bytes_new (transfer->buffer,
                            MIN ((gsize) transfer->actual_length, cmd->read_len));

  fpi_ssm_next_state (transfer->ssm);
}

static void
rtk_cmd_status_cb (FpiUsbTransfer *transfer,
                   FpDevice       *dev,
                   gpointer        user_data,
                   GError         *error)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  RtkCmd *cmd = fpi_ssm_get_data (transfer->ssm);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (transfer->actual_length == 0)
    {
      fpi_ssm_jump_to_state (transfer->ssm, CMD_STATUS);
      return;
    }

  memset (self->status, 0xff, STATUS_LEN);
  memcpy (self->status, transfer->buffer, MIN (transfer->actual_length, STATUS_LEN));

  if (cmd->check_status && self->status[0] != 0)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "Command %02x %02x failed with status "
                                                     "%02x%02x%02x%02x%02x",
                                                     cmd->header[0], cmd->header[1],
                                                     self->status[0], self->status[1],
                                                     self->status[2], self->status[3],
                                                     self->status[4]));
      return;
    }

  fpi_ssm_mark_completed (transfer->ssm);
}

static void
rtk_cmd_run_state (FpiSsm *ssm, FpDevice *dev)
{
  RtkCmd *cmd = fpi_ssm_get_data (ssm);
  FpiUsbTransfer *transfer;
  guint cmd_type = (cmd->header[0] & 0xc0) >> 6;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CMD_SEND:
      transfer = fpi_usb_transfer_new (dev);
      transfer->ssm = ssm;
      transfer->short_is_error = TRUE;
      fpi_usb_transfer_fill_bulk_full (transfer, EP_OUT,
                                       g_memdup2 (cmd->header, CMD_LEN), CMD_LEN,
                                       g_free);
      fpi_usb_transfer_submit (transfer, CMD_TIMEOUT, NULL,
                               fpi_ssm_usb_transfer_cb, NULL);
      break;

    case CMD_WRITE:
      if (cmd_type != 2 || !cmd->write_data)
        {
          fpi_ssm_next_state (ssm);
          break;
        }
      transfer = fpi_usb_transfer_new (dev);
      transfer->ssm = ssm;
      transfer->short_is_error = TRUE;
      fpi_usb_transfer_fill_bulk_full (transfer, EP_OUT,
                                       g_memdup2 (g_bytes_get_data (cmd->write_data, NULL),
                                                  g_bytes_get_size (cmd->write_data)),
                                       g_bytes_get_size (cmd->write_data),
                                       g_free);
      fpi_usb_transfer_submit (transfer, DATA_TIMEOUT, NULL,
                               fpi_ssm_usb_transfer_cb, NULL);
      break;

    case CMD_READ:
      if (cmd_type != 1 || cmd->read_len == 0)
        {
          fpi_ssm_next_state (ssm);
          break;
        }
      transfer = fpi_usb_transfer_new (dev);
      transfer->ssm = ssm;
      fpi_usb_transfer_fill_bulk (transfer, EP_IN, EP_IN_BUF_SIZE);
      fpi_usb_transfer_submit (transfer, DATA_TIMEOUT, NULL,
                               rtk_cmd_read_cb, NULL);
      break;

    case CMD_STATUS:
      transfer = fpi_usb_transfer_new (dev);
      transfer->ssm = ssm;
      fpi_usb_transfer_fill_bulk (transfer, EP_IN, EP_IN_BUF_SIZE);
      fpi_usb_transfer_submit (transfer, STATUS_TIMEOUT, NULL,
                               rtk_cmd_status_cb, NULL);
      break;
    }
}

/* Run one command as a sub state machine of @parent. Takes @write_data. */
static void
rtk_cmd (FpiSsm  *parent,
         guint8   c0,
         guint8   c1,
         guint8   p0,
         guint8   p1,
         GBytes  *write_data,
         gsize    read_len,
         gboolean check_status)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (fpi_ssm_get_device (parent));
  RtkCmd *cmd = g_new0 (RtkCmd, 1);
  gsize data_len = write_data ? g_bytes_get_size (write_data) : read_len;
  FpiSsm *ssm;

  cmd->header[0] = c0;
  cmd->header[1] = c1;
  cmd->header[2] = p0;
  cmd->header[3] = p1;
  cmd->header[10] = data_len & 0xff;
  cmd->header[11] = (data_len >> 8) & 0xff;
  cmd->write_data = write_data;
  cmd->read_len = read_len;
  cmd->check_status = check_status;

  g_clear_pointer (&self->resp, g_bytes_unref);

  ssm = fpi_ssm_new (FP_DEVICE (self), rtk_cmd_run_state, CMD_NUM_STATES);
  fpi_ssm_set_data (ssm, cmd, (GDestroyNotify) rtk_cmd_free);
  fpi_ssm_silence_debug (ssm);
  fpi_ssm_start_subsm (parent, ssm);
}

static const guint8 *
resp_data (FpiDeviceRealtekSdcp *self, gsize min_len)
{
  gsize len = 0;
  const guint8 *data;

  if (!self->resp)
    return NULL;

  data = g_bytes_get_data (self->resp, &len);
  return len >= min_len ? data : NULL;
}

static void
rtk_get_slot_table (FpiSsm *ssm)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (fpi_ssm_get_device (ssm));

  rtk_cmd (ssm, 0x45, 0x0e, 0, 0, NULL, SLOT_LEN * self->slots, TRUE);
}

static GError *
retry_error_for_status (guint8 status)
{
  switch (status)
    {
    case 0x01: /* too high */
    case 0x02: /* too low */
    case 0x03: /* too left */
    case 0x04: /* too right */
      return fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);

    case 0x05:
      return fpi_device_retry_new (FP_DEVICE_RETRY_TOO_FAST);

    case 0x09:
      return fpi_device_retry_new (FP_DEVICE_RETRY_TOO_SHORT);

    default:
      return fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL);
    }
}

/******************************************************************************
 * Capture helper states, shared by identify and enroll:
 * start capture, poll until a finger was captured, accept the sample.
 * Returns TRUE if the state was handled.
 */

static void
capture_start (FpiSsm *ssm, guint8 purpose)
{
  FpDevice *dev = fpi_ssm_get_device (ssm);
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);

  self->capture_purpose = purpose;
  fpi_device_report_finger_status_changes (dev,
                                           FP_FINGER_STATUS_NEEDED,
                                           FP_FINGER_STATUS_NONE);
  rtk_cmd (ssm, 0x05, 0x05, purpose, 0x02, NULL, 0, TRUE);
}

static void
capture_poll (FpiSsm *ssm)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (fpi_ssm_get_device (ssm));

  rtk_cmd (ssm, 0x45, 0x06, self->capture_purpose, 0x02, NULL, CAPTURE_POLL_LEN, FALSE);
}

/* Returns TRUE once a finger has been captured; otherwise re-schedules the
 * poll state (or fails the machine on cancellation). */
static gboolean
capture_poll_check (FpiSsm *ssm, gint poll_state, gint cancel_state)
{
  FpDevice *dev = fpi_ssm_get_device (ssm);
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  const guint8 *data = resp_data (self, 1);

  if (data && data[0] == 0)
    {
      fpi_device_report_finger_status_changes (dev,
                                               FP_FINGER_STATUS_PRESENT,
                                               FP_FINGER_STATUS_NEEDED);
      return TRUE;
    }

  if (g_cancellable_is_cancelled (fpi_device_get_cancellable (dev)))
    {
      self->cancelled = TRUE;
      fpi_ssm_jump_to_state (ssm, cancel_state);
    }
  else
    fpi_ssm_jump_to_state_delayed (ssm, poll_state, POLL_INTERVAL);

  return FALSE;
}

static void
capture_accept (FpiSsm *ssm)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (fpi_ssm_get_device (ssm));

  rtk_cmd (ssm, 0x45, 0x08, self->capture_purpose, 0, NULL, ACCEPT_SAMPLE_LEN, FALSE);
}

/* Returns the accept-sample status byte (0 = good sample) */
static guint8
capture_accept_status (FpiSsm *ssm)
{
  FpDevice *dev = fpi_ssm_get_device (ssm);
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  const guint8 *data = resp_data (self, 1);

  fpi_device_report_finger_status_changes (dev,
                                           FP_FINGER_STATUS_NONE,
                                           FP_FINGER_STATUS_PRESENT);

  return data ? data[0] : IN_STATUS_CMD_ERR;
}

static void
capture_cancel (FpiSsm *ssm)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (fpi_ssm_get_device (ssm));

  rtk_cmd (ssm, 0x05, 0x07, self->capture_purpose, 0, NULL, 0, FALSE);
}

static GError *
cancelled_error (void)
{
  return g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation was cancelled");
}

/* Send an identify nonce and read back the result. */
static void
identify_send_nonce (FpiSsm *ssm, GBytes *nonce)
{
  rtk_cmd (ssm, 0x85, 0x0b, 0, 0, nonce, 0, TRUE);
}

static void
identify_read_result (FpiSsm *ssm)
{
  /* The status phase reports failure on "no match", so don't check it */
  rtk_cmd (ssm, 0x45, 0x0c, 0x00, 0x02, NULL, IDENTIFY_RESULT_LEN, FALSE);
}

/* Parse the identify result: status || subfactor || id(32) || mac(32) || ... */
static gboolean
identify_parse_result (FpiDeviceRealtekSdcp *self)
{
  const guint8 *data = resp_data (self, 2 + FPI_SDCP_ENROLLMENT_ID_SIZE + FPI_SDCP_MAC_SIZE);

  g_clear_pointer (&self->identify_id, g_bytes_unref);
  g_clear_pointer (&self->identify_mac, g_bytes_unref);

  if (!data || data[0] != IN_STATUS_SUCCESS)
    return FALSE;

  self->identify_id = g_bytes_new (data + 2, FPI_SDCP_ENROLLMENT_ID_SIZE);
  self->identify_mac = g_bytes_new (data + 2 + FPI_SDCP_ENROLLMENT_ID_SIZE, FPI_SDCP_MAC_SIZE);
  return TRUE;
}

/******************************************************************************
 * Open
 */

enum {
  OPEN_SELECT_OS,
  OPEN_GET_ENROLL_NUM,
  OPEN_SAVE_ENROLL_NUM,
  OPEN_NUM_STATES,
};

static void
open_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  const guint8 *data;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_SELECT_OS:
      /* Windows selects OS 0; the SDCP session and storage live there */
      rtk_cmd (ssm, 0x05, 0x13, 0x00, 0, NULL, 0, TRUE);
      break;

    case OPEN_GET_ENROLL_NUM:
      rtk_cmd (ssm, 0x45, 0x0d, 0, 0, NULL, 2, TRUE);
      break;

    case OPEN_SAVE_ENROLL_NUM:
      data = resp_data (self, 2);
      if (!data || data[1] == 0)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                              "Invalid template count"));
          return;
        }
      self->slots = data[1];
      fp_dbg ("Device has %u template slots", self->slots);
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
open_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);

  self->task_ssm = NULL;

  /* Continues with SDCP connect or reconnect */
  fpi_sdcp_device_open_complete (FP_SDCP_DEVICE (dev), error);
}

static void
dev_open (FpSdcpDevice *sdcp_device)
{
  FpDevice *dev = FP_DEVICE (sdcp_device);
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  GError *error = NULL;

  G_DEBUG_HERE ();

  if (!g_usb_device_reset (fpi_device_get_usb_device (dev), &error) ||
      !g_usb_device_claim_interface (fpi_device_get_usb_device (dev), 0, 0, &error))
    {
      fpi_sdcp_device_open_complete (sdcp_device, error);
      return;
    }

  g_assert (!self->task_ssm);
  self->task_ssm = fpi_ssm_new (dev, open_run_state, OPEN_NUM_STATES);
  fpi_ssm_start (self->task_ssm, open_ssm_done);
}

/******************************************************************************
 * SDCP connect / reconnect
 */

enum {
  CONNECT_REQUEST,
  CONNECT_RESPONSE,
  CONNECT_NUM_STATES,
};

static GBytes *
length_prefixed (GBytes *data)
{
  gsize len = g_bytes_get_size (data);
  guint8 *buf = g_malloc (len + 2);

  buf[0] = len & 0xff;
  buf[1] = (len >> 8) & 0xff;
  memcpy (buf + 2, g_bytes_get_data (data, NULL), len);
  return g_bytes_new_take (buf, len + 2);
}

static void
connect_run_state (FpiSsm *ssm, FpDevice *dev)
{
  g_autoptr(GBytes) host_random = NULL;
  g_autoptr(GBytes) host_public_key = NULL;
  g_autoptr(GBytes) random_lv = NULL;
  g_autoptr(GBytes) key_lv = NULL;
  GByteArray *req;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CONNECT_REQUEST:
      /* ConnectRequest: [len] r_h [len] pk_h */
      fpi_sdcp_device_get_connect_data (FP_SDCP_DEVICE (dev), &host_random, &host_public_key);
      random_lv = length_prefixed (host_random);
      key_lv = length_prefixed (host_public_key);
      req = g_byte_array_new ();
      g_byte_array_append (req, g_bytes_get_data (random_lv, NULL), g_bytes_get_size (random_lv));
      g_byte_array_append (req, g_bytes_get_data (key_lv, NULL), g_bytes_get_size (key_lv));
      rtk_cmd (ssm, 0x85, 0x01, 0, 0, g_byte_array_free_to_bytes (req), 0, TRUE);
      break;

    case CONNECT_RESPONSE:
      rtk_cmd (ssm, 0x45, 0x02, 0, 0, NULL, CONNECT_RESPONSE_LEN, TRUE);
      break;
    }
}

/* Read a 2-byte little endian length prefixed field from @resp at *@offset */
static GBytes *
take_lv (GBytes *resp, gsize *offset)
{
  gsize size = 0;
  const guint8 *data = g_bytes_get_data (resp, &size);
  gsize len;

  if (*offset + 2 > size)
    return NULL;

  len = data[*offset] | (data[*offset + 1] << 8);
  if (*offset + 2 + len > size)
    return NULL;

  *offset += 2 + len;
  return g_bytes_new_from_bytes (resp, *offset - len, len);
}

static void
connect_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  g_autoptr(GBytes) device_random = NULL;
  g_autoptr(GBytes) claim_bytes = NULL;
  g_autoptr(GBytes) mac = NULL;
  g_autoptr(FpiSdcpClaim) claim = NULL;
  const guint8 *c;
  gsize claim_len = 0;
  gsize offset = 0;
  gsize cert_len;

  self->task_ssm = NULL;

  if (error)
    {
      fpi_sdcp_device_connect_complete (FP_SDCP_DEVICE (dev), NULL, NULL, NULL, error);
      return;
    }

  /* ConnectResponse: [len] r_d [len] claim [len] mac, then zero padding */
  device_random = take_lv (self->resp, &offset);
  claim_bytes = take_lv (self->resp, &offset);
  mac = take_lv (self->resp, &offset);

  if (!device_random || !claim_bytes || !mac)
    goto invalid;

  /* claim = cert_m (DER) || pk_d || pk_f || h_f || s_m || s_d */
  c = g_bytes_get_data (claim_bytes, &claim_len);
  if (claim_len < 4 || c[0] != 0x30 || c[1] != 0x82)
    goto invalid;

  cert_len = 4 + ((c[2] << 8) | c[3]);
  if (claim_len != cert_len + 2 * FPI_SDCP_PUBLIC_KEY_SIZE + FPI_SDCP_DIGEST_SIZE +
      2 * FPI_SDCP_SIGNATURE_SIZE)
    goto invalid;

  claim = fpi_sdcp_claim_new ();
  offset = 0;
  claim->model_certificate = g_bytes_new_from_bytes (claim_bytes, offset, cert_len);
  offset += cert_len;
  claim->device_public_key = g_bytes_new_from_bytes (claim_bytes, offset, FPI_SDCP_PUBLIC_KEY_SIZE);
  offset += FPI_SDCP_PUBLIC_KEY_SIZE;
  claim->firmware_public_key = g_bytes_new_from_bytes (claim_bytes, offset, FPI_SDCP_PUBLIC_KEY_SIZE);
  offset += FPI_SDCP_PUBLIC_KEY_SIZE;
  claim->firmware_hash = g_bytes_new_from_bytes (claim_bytes, offset, FPI_SDCP_DIGEST_SIZE);
  offset += FPI_SDCP_DIGEST_SIZE;
  claim->model_signature = g_bytes_new_from_bytes (claim_bytes, offset, FPI_SDCP_SIGNATURE_SIZE);
  offset += FPI_SDCP_SIGNATURE_SIZE;
  claim->device_signature = g_bytes_new_from_bytes (claim_bytes, offset, FPI_SDCP_SIGNATURE_SIZE);

  fpi_sdcp_device_connect_complete (FP_SDCP_DEVICE (dev),
                                    g_steal_pointer (&device_random),
                                    g_steal_pointer (&claim),
                                    g_steal_pointer (&mac),
                                    NULL);
  return;

invalid:
  fpi_sdcp_device_connect_complete (FP_SDCP_DEVICE (dev), NULL, NULL, NULL,
                                    fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                              "Malformed SDCP ConnectResponse"));
}

static void
dev_connect (FpSdcpDevice *sdcp_device)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (sdcp_device);

  G_DEBUG_HERE ();

  g_assert (!self->task_ssm);
  self->task_ssm = fpi_ssm_new (FP_DEVICE (self), connect_run_state, CONNECT_NUM_STATES);
  fpi_ssm_start (self->task_ssm, connect_ssm_done);
}

enum {
  RECONNECT_REQUEST,
  RECONNECT_RESPONSE,
  RECONNECT_NUM_STATES,
};

static void
reconnect_run_state (FpiSsm *ssm, FpDevice *dev)
{
  g_autoptr(GBytes) random = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case RECONNECT_REQUEST:
      fpi_sdcp_device_get_reconnect_data (FP_SDCP_DEVICE (dev), &random);
      rtk_cmd (ssm, 0x85, 0x03, 0, 0, length_prefixed (random), 0, TRUE);
      break;

    case RECONNECT_RESPONSE:
      rtk_cmd (ssm, 0x45, 0x04, 0, 0, NULL, 2 + FPI_SDCP_MAC_SIZE, TRUE);
      break;
    }
}

static void
reconnect_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  gsize offset = 0;
  GBytes *mac = NULL;

  self->task_ssm = NULL;

  if (!error)
    {
      mac = take_lv (self->resp, &offset);
      if (!mac || g_bytes_get_size (mac) != FPI_SDCP_MAC_SIZE)
        {
          g_clear_pointer (&mac, g_bytes_unref);
          error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Malformed reconnect response");
        }
    }

  /* On error the base class falls back to a full connect */
  fpi_sdcp_device_reconnect_complete (FP_SDCP_DEVICE (dev), mac, error);
}

static void
dev_reconnect (FpSdcpDevice *sdcp_device)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (sdcp_device);

  G_DEBUG_HERE ();

  g_assert (!self->task_ssm);
  self->task_ssm = fpi_ssm_new (FP_DEVICE (self), reconnect_run_state, RECONNECT_NUM_STATES);
  fpi_ssm_start (self->task_ssm, reconnect_ssm_done);
}

/******************************************************************************
 * Identify / verify
 */

enum {
  IDENTIFY_CAPTURE,
  IDENTIFY_POLL,
  IDENTIFY_POLL_CHECK,
  IDENTIFY_ACCEPT,
  IDENTIFY_ACCEPT_CHECK,
  IDENTIFY_SLOT_TABLE,
  IDENTIFY_NONCE,
  IDENTIFY_RESULT,
  IDENTIFY_PARSE,
  IDENTIFY_CANCEL,
  IDENTIFY_NUM_STATES,
};

static void
identify_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  g_autoptr(GBytes) nonce = NULL;
  guint8 st;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case IDENTIFY_CAPTURE:
      capture_start (ssm, PURPOSE_IDENTIFY);
      break;

    case IDENTIFY_POLL:
      capture_poll (ssm);
      break;

    case IDENTIFY_POLL_CHECK:
      if (capture_poll_check (ssm, IDENTIFY_POLL, IDENTIFY_CANCEL))
        fpi_ssm_next_state (ssm);
      break;

    case IDENTIFY_ACCEPT:
      capture_accept (ssm);
      break;

    case IDENTIFY_ACCEPT_CHECK:
      st = capture_accept_status (ssm);
      if (st != IN_STATUS_SUCCESS)
        {
          /* Bad sample: report a retry and finish this verify/identify */
          self->retry_error = retry_error_for_status (st);
          fpi_ssm_mark_completed (ssm);
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case IDENTIFY_SLOT_TABLE:
      /* Windows reads the slot table between capture and identify */
      rtk_get_slot_table (ssm);
      break;

    case IDENTIFY_NONCE:
      fpi_sdcp_device_get_identify_data (FP_SDCP_DEVICE (dev), &nonce);
      identify_send_nonce (ssm, g_steal_pointer (&nonce));
      break;

    case IDENTIFY_RESULT:
      identify_read_result (ssm);
      break;

    case IDENTIFY_PARSE:
      identify_parse_result (self);
      fpi_ssm_mark_completed (ssm);
      break;

    case IDENTIFY_CANCEL:
      capture_cancel (ssm);
      break;
    }
}

static void
identify_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  FpSdcpDevice *sdcp_device = FP_SDCP_DEVICE (dev);

  self->task_ssm = NULL;

  if (!error && self->cancelled)
    error = cancelled_error ();

  if (error)
    {
      g_clear_pointer (&self->retry_error, g_error_free);
      fpi_sdcp_device_identify_complete (sdcp_device, NULL, NULL, error);
      return;
    }

  if (self->retry_error)
    {
      fpi_sdcp_device_identify_retry (sdcp_device, g_steal_pointer (&self->retry_error));
      if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_complete (dev, NULL);
      else
        fpi_device_identify_complete (dev, NULL);
      return;
    }

  /* NULL id/mac means "no match" to the base class */
  fpi_sdcp_device_identify_complete (sdcp_device,
                                     g_steal_pointer (&self->identify_id),
                                     g_steal_pointer (&self->identify_mac),
                                     NULL);
}

static void
dev_identify (FpSdcpDevice *sdcp_device)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (sdcp_device);

  G_DEBUG_HERE ();

  self->cancelled = FALSE;
  g_assert (!self->task_ssm);
  self->task_ssm = fpi_ssm_new_full (FP_DEVICE (self), identify_run_state,
                                     IDENTIFY_NUM_STATES, IDENTIFY_NUM_STATES,
                                     "Identify");
  fpi_ssm_start (self->task_ssm, identify_ssm_done);
}

/******************************************************************************
 * Enroll
 *
 * The firmware only hands out an enrollment nonce right after an identify
 * that found no match, so we start with one identify touch (which also
 * rejects fingers that are already enrolled), then fetch the nonce and
 * collect the samples.
 */

enum {
  ENROLL_PRE_CAPTURE,
  ENROLL_PRE_POLL,
  ENROLL_PRE_POLL_CHECK,
  ENROLL_PRE_ACCEPT,
  ENROLL_PRE_ACCEPT_CHECK,
  ENROLL_PRE_SLOT_TABLE,
  ENROLL_PRE_NONCE,
  ENROLL_PRE_RESULT,
  ENROLL_PRE_PARSE,
  ENROLL_SLOT_TABLE,
  ENROLL_GET_NONCE,
  ENROLL_SAVE_NONCE,
  ENROLL_CAPTURE,
  ENROLL_POLL,
  ENROLL_POLL_CHECK,
  ENROLL_ACCEPT,
  ENROLL_ACCEPT_CHECK,
  ENROLL_DUP_CHECK,
  ENROLL_DUP_CHECK_RESULT,
  ENROLL_FINAL_SLOT_TABLE,
  ENROLL_DONE,
  ENROLL_CANCEL,
  ENROLL_NUM_STATES,
};

/* Fixed nonce for the pre-enroll identify in emulation (test) mode, so that
 * recorded USB traffic replays deterministically */
static const guint8 emulation_pre_enroll_nonce[FPI_SDCP_NONCE_SIZE] = {
  0x52, 0x54, 0x4b, 0x2d, 0x53, 0x44, 0x43, 0x50, 0x2d, 0x70, 0x72, 0x65, 0x2d, 0x65, 0x6e, 0x72,
  0x6f, 0x6c, 0x6c, 0x2d, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x30, 0x31,
};

static void
enroll_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  g_autoptr(GError) error = NULL;
  GBytes *nonce;
  const guint8 *data;
  guint8 st;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ENROLL_PRE_CAPTURE:
      capture_start (ssm, PURPOSE_IDENTIFY);
      break;

    case ENROLL_PRE_POLL:
      capture_poll (ssm);
      break;

    case ENROLL_PRE_POLL_CHECK:
      if (capture_poll_check (ssm, ENROLL_PRE_POLL, ENROLL_CANCEL))
        fpi_ssm_next_state (ssm);
      break;

    case ENROLL_PRE_ACCEPT:
      capture_accept (ssm);
      break;

    case ENROLL_PRE_ACCEPT_CHECK:
      st = capture_accept_status (ssm);
      if (st != IN_STATUS_SUCCESS)
        {
          fpi_device_enroll_progress (dev, self->enroll_stage, NULL,
                                      retry_error_for_status (st));
          fpi_ssm_jump_to_state (ssm, ENROLL_PRE_CAPTURE);
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case ENROLL_PRE_SLOT_TABLE:
      rtk_get_slot_table (ssm);
      break;

    case ENROLL_PRE_NONCE:
      if (fpi_device_emulation_mode_enabled (dev))
        nonce = g_bytes_new_static (emulation_pre_enroll_nonce, sizeof (emulation_pre_enroll_nonce));
      else
        nonce = fpi_sdcp_generate_random (&error);
      if (!nonce)
        {
          fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
          return;
        }
      identify_send_nonce (ssm, nonce);
      break;

    case ENROLL_PRE_RESULT:
      identify_read_result (ssm);
      break;

    case ENROLL_PRE_PARSE:
      if (identify_parse_result (self))
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_DATA_DUPLICATE));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case ENROLL_SLOT_TABLE:
      rtk_get_slot_table (ssm);
      break;

    case ENROLL_GET_NONCE:
      rtk_cmd (ssm, 0x45, 0x09, 0, 0, NULL, FPI_SDCP_NONCE_SIZE, FALSE);
      break;

    case ENROLL_SAVE_NONCE:
      data = resp_data (self, FPI_SDCP_NONCE_SIZE);
      if (self->status[0] != 0 || !data)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                         "The reader refused to start an enrollment. "
                                                         "Fingerprints stored by another system "
                                                         "(e.g. Windows Hello) can block this; "
                                                         "clearing the device storage may help."));
          return;
        }
      g_clear_pointer (&self->enroll_nonce, g_bytes_unref);
      self->enroll_nonce = g_bytes_new (data, FPI_SDCP_NONCE_SIZE);
      fpi_ssm_next_state (ssm);
      break;

    case ENROLL_CAPTURE:
      capture_start (ssm, PURPOSE_ENROLL);
      break;

    case ENROLL_POLL:
      capture_poll (ssm);
      break;

    case ENROLL_POLL_CHECK:
      if (capture_poll_check (ssm, ENROLL_POLL, ENROLL_CANCEL))
        fpi_ssm_next_state (ssm);
      break;

    case ENROLL_ACCEPT:
      capture_accept (ssm);
      break;

    case ENROLL_ACCEPT_CHECK:
      st = capture_accept_status (ssm);
      if (st == IN_STATUS_CMD_ERR)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                              "Command error while enrolling"));
          return;
        }
      if (st != IN_STATUS_SUCCESS)
        {
          fpi_device_enroll_progress (dev, self->enroll_stage, NULL,
                                      retry_error_for_status (st));
          fpi_ssm_jump_to_state (ssm, ENROLL_CAPTURE);
          return;
        }

      self->enroll_stage++;
      fpi_device_enroll_progress (dev, self->enroll_stage, NULL, NULL);

      if (self->enroll_stage < ENROLL_SAMPLES)
        fpi_ssm_jump_to_state (ssm, ENROLL_CAPTURE);
      else
        fpi_ssm_next_state (ssm);
      break;

    case ENROLL_DUP_CHECK:
      rtk_cmd (ssm, 0x45, 0x10, 0x01, 0, NULL, DUP_CHECK_LEN, FALSE);
      break;

    case ENROLL_DUP_CHECK_RESULT:
      data = resp_data (self, 1);
      if (data && data[0] == IN_STATUS_SUCCESS)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_DATA_DUPLICATE));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case ENROLL_FINAL_SLOT_TABLE:
      rtk_get_slot_table (ssm);
      break;

    case ENROLL_DONE:
      fpi_ssm_mark_completed (ssm);
      break;

    case ENROLL_CANCEL:
      capture_cancel (ssm);
      break;
    }
}

static void
enroll_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);

  self->task_ssm = NULL;

  if (!error && self->cancelled)
    error = cancelled_error ();

  if (error)
    {
      g_clear_pointer (&self->enroll_nonce, g_bytes_unref);
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  /* The base class derives the enrollment id and calls dev_enroll_commit () */
  fpi_sdcp_device_enroll_commit (FP_SDCP_DEVICE (dev), self->enroll_nonce, NULL);
  g_clear_pointer (&self->enroll_nonce, g_bytes_unref);
}

static void
dev_enroll (FpSdcpDevice *sdcp_device)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (sdcp_device);

  G_DEBUG_HERE ();

  self->enroll_stage = 0;
  self->cancelled = FALSE;

  g_assert (!self->task_ssm);
  self->task_ssm = fpi_ssm_new_full (FP_DEVICE (self), enroll_run_state,
                                     ENROLL_NUM_STATES, ENROLL_NUM_STATES,
                                     "Enroll");
  fpi_ssm_start (self->task_ssm, enroll_ssm_done);
}

enum {
  COMMIT_SEND,
  COMMIT_NUM_STATES,
};

static void
commit_run_state (FpiSsm *ssm, FpDevice *dev)
{
  GBytes *id = fpi_ssm_get_data (ssm);
  GByteArray *payload;
  guint8 zero = 0;
  guint8 pad[16];

  /* Commit payload as sent by Windows: id || 00 || ff * 16 */
  memset (pad, 0xff, sizeof (pad));
  payload = g_byte_array_new ();
  g_byte_array_append (payload, g_bytes_get_data (id, NULL), g_bytes_get_size (id));
  g_byte_array_append (payload, &zero, 1);
  g_byte_array_append (payload, pad, sizeof (pad));

  rtk_cmd (ssm, 0x85, 0x0a, SUBFACTOR, 0, g_byte_array_free_to_bytes (payload), 0, TRUE);
}

static void
commit_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);

  self->task_ssm = NULL;
  fpi_sdcp_device_enroll_commit_complete (FP_SDCP_DEVICE (dev), error);
}

static void
dev_enroll_commit (FpSdcpDevice *sdcp_device, GBytes *id)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (sdcp_device);

  G_DEBUG_HERE ();

  if (!id)
    {
      fpi_sdcp_device_enroll_commit_complete (sdcp_device,
                                              fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
      return;
    }

  g_assert (!self->task_ssm);
  self->task_ssm = fpi_ssm_new (FP_DEVICE (self), commit_run_state, COMMIT_NUM_STATES);
  fpi_ssm_set_data (self->task_ssm, g_bytes_ref (id), (GDestroyNotify) g_bytes_unref);
  fpi_ssm_start (self->task_ssm, commit_ssm_done);
}

/******************************************************************************
 * Storage: list, delete, clear
 *
 * The slot table only holds SHA256(enrollment id), not the id itself, so
 * listing reports those hashes as ids. Delete accepts either a real id (as
 * stored by fprintd) or such a hash.
 */

enum {
  STORAGE_SLOT_TABLE,
  STORAGE_ACT,
  STORAGE_NUM_STATES,
};

static gboolean
slot_used (const guint8 *table, guint slot)
{
  return table[slot * SLOT_LEN] != 0;
}

static const guint8 *
slot_hash (const guint8 *table, guint slot)
{
  return table + slot * SLOT_LEN + SLOT_HASH_OFFSET;
}

static void
list_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case STORAGE_SLOT_TABLE:
      rtk_get_slot_table (ssm);
      break;

    case STORAGE_ACT:
      if (!resp_data (self, SLOT_LEN * self->slots))
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
          return;
        }
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
list_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  GPtrArray *ids;
  const guint8 *table;

  self->task_ssm = NULL;

  if (error)
    {
      fpi_sdcp_device_list_complete (FP_SDCP_DEVICE (dev), NULL, error);
      return;
    }

  table = resp_data (self, SLOT_LEN * self->slots);
  ids = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  for (guint i = 0; i < self->slots; i++)
    if (slot_used (table, i))
      g_ptr_array_add (ids, g_bytes_new (slot_hash (table, i), FPI_SDCP_ENROLLMENT_ID_SIZE));

  fpi_sdcp_device_list_complete (FP_SDCP_DEVICE (dev), ids, NULL);
}

static void
dev_list (FpSdcpDevice *sdcp_device)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (sdcp_device);

  G_DEBUG_HERE ();

  g_assert (!self->task_ssm);
  self->task_ssm = fpi_ssm_new (FP_DEVICE (self), list_run_state, STORAGE_NUM_STATES);
  fpi_ssm_start (self->task_ssm, list_ssm_done);
}

static gint
find_slot (FpiDeviceRealtekSdcp *self, const guint8 *table, GBytes *id)
{
  guint8 digest[32];
  gsize digest_len = sizeof (digest);
  GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
  gsize id_len = 0;
  const guint8 *id_data = g_bytes_get_data (id, &id_len);

  g_checksum_update (checksum, id_data, id_len);
  g_checksum_get_digest (checksum, digest, &digest_len);
  g_checksum_free (checksum);

  for (guint i = 0; i < self->slots; i++)
    {
      if (!slot_used (table, i))
        continue;
      if (memcmp (slot_hash (table, i), digest, sizeof (digest)) == 0)
        return i;
      if (id_len == FPI_SDCP_ENROLLMENT_ID_SIZE &&
          memcmp (slot_hash (table, i), id_data, id_len) == 0)
        return i;
    }

  return -1;
}

static void
delete_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);
  const guint8 *table;
  g_autoptr(GBytes) id = NULL;
  FpPrint *print = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case STORAGE_SLOT_TABLE:
      rtk_get_slot_table (ssm);
      break;

    case STORAGE_ACT:
      table = resp_data (self, SLOT_LEN * self->slots);
      fpi_device_get_delete_data (dev, &print);
      id = fpi_print_sdcp_get_id (print);
      if (!table || !id || (self->delete_slot = find_slot (self, table, id)) < 0)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new (FP_DEVICE_ERROR_DATA_NOT_FOUND));
          return;
        }
      fp_dbg ("Deleting template in slot %d", self->delete_slot);
      rtk_cmd (ssm, 0x05, 0x0f, self->delete_slot, 0, NULL, 0, TRUE);
      break;
    }
}

static void
delete_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);

  self->task_ssm = NULL;
  fpi_device_delete_complete (dev, error);
}

static void
dev_delete (FpDevice *dev)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);

  G_DEBUG_HERE ();

  g_assert (!self->task_ssm);
  self->task_ssm = fpi_ssm_new (dev, delete_run_state, STORAGE_NUM_STATES);
  fpi_ssm_start (self->task_ssm, delete_ssm_done);
}

static void
clear_run_state (FpiSsm *ssm, FpDevice *dev)
{
  rtk_cmd (ssm, 0x05, 0x0f, 0xff, 0, NULL, 0, TRUE);
}

static void
clear_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);

  self->task_ssm = NULL;
  fpi_device_clear_storage_complete (dev, error);
}

static void
dev_clear_storage (FpDevice *dev)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (dev);

  G_DEBUG_HERE ();

  g_assert (!self->task_ssm);
  self->task_ssm = fpi_ssm_new (dev, clear_run_state, 1);
  fpi_ssm_start (self->task_ssm, clear_ssm_done);
}

/******************************************************************************
 * Close / object
 */

static void
dev_close (FpDevice *dev)
{
  g_autoptr(GError) release_error = NULL;

  G_DEBUG_HERE ();

  g_usb_device_release_interface (fpi_device_get_usb_device (dev), 0, 0, &release_error);
  fpi_device_close_complete (dev, g_steal_pointer (&release_error));
}

static void
fpi_device_realtek_sdcp_finalize (GObject *object)
{
  FpiDeviceRealtekSdcp *self = FPI_DEVICE_REALTEK_SDCP (object);

  g_clear_pointer (&self->resp, g_bytes_unref);
  g_clear_pointer (&self->enroll_nonce, g_bytes_unref);
  g_clear_pointer (&self->identify_id, g_bytes_unref);
  g_clear_pointer (&self->identify_mac, g_bytes_unref);
  g_clear_pointer (&self->retry_error, g_error_free);

  G_OBJECT_CLASS (fpi_device_realtek_sdcp_parent_class)->finalize (object);
}

static void
fpi_device_realtek_sdcp_init (FpiDeviceRealtekSdcp *self)
{
}

static void
fpi_device_realtek_sdcp_class_init (FpiDeviceRealtekSdcpClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpSdcpDeviceClass *sdcp_class = FP_SDCP_DEVICE_CLASS (klass);

  object_class->finalize = fpi_device_realtek_sdcp_finalize;

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = "Realtek MoC Fingerprint Sensor (SDCP)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = ENROLL_SAMPLES;
  dev_class->temp_hot_seconds = -1;

  dev_class->close = dev_close;
  dev_class->delete = dev_delete;
  dev_class->clear_storage = dev_clear_storage;

  /* The model certificate is genuine (it chains to Microsoft's Windows Hello
   * CA) but expired in 2025; Windows does not check the validity period
   * either. All other verification stays enabled. */
  sdcp_class->verification_flags = FPI_DEVICE_SDCP_VERIFICATION_CERTIFICATE_NO_CHECK_TIME;

  sdcp_class->open = dev_open;
  sdcp_class->connect = dev_connect;
  sdcp_class->reconnect = dev_reconnect;
  sdcp_class->list = dev_list;
  sdcp_class->enroll = dev_enroll;
  sdcp_class->enroll_commit = dev_enroll_commit;
  sdcp_class->identify = dev_identify;

  fpi_device_class_auto_initialize_features (dev_class);
  dev_class->features |= FP_DEVICE_FEATURE_STORAGE | FP_DEVICE_FEATURE_DUPLICATES_CHECK;
}
