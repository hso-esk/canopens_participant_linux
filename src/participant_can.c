/*
 * Copyright (c) 2026
 *
 * Hochschule Offenburg, University of Applied Sciences
 * Institute for reliable Embedded Systems
 * and Communications Electronic (ivESK)
 *
 * This file is licensed as described in the "LICENSE" file
 * included within the root folder of this work.
 */

#include "participant_channel.h"
#include "spsec_common.h"
#include "spsec_protocol_can.h"

static const char *logger_name_ptr = "participant_can";

// Set up the secure SPsec channel on interface_name_ptr.
signed char participant_secure_channel_init(SPsecCommChannel *channel_ptr,
                                            const char *interface_name_ptr,
                                            uint8_t *participant_id_ptr) {
  if (!channel_ptr || !interface_name_ptr || !participant_id_ptr)
    return -1;
  channel_ptr->participant_id = *participant_id_ptr;
  LOG_DEBUG(logger_name_ptr, "Initializing participant channel with ID: %u (0x%x)",
            channel_ptr->participant_id, channel_ptr->participant_id);
  return can_channel_init(&channel_ptr->channel, interface_name_ptr, 500000, 2000000);
}

// Set up the plain (insecure) CAN channel on interface_name_ptr.
signed char participant_insecure_channel_init(CommChannel *channel_ptr,
                                              const char *interface_name_ptr) {
  return can_channel_init(channel_ptr, interface_name_ptr, 500000, 2000000);
}

// Close the socket and free a secure channel's resources.
void participant_channel_destroy(SPsecCommChannel *channel_ptr) {
  can_channel_destroy(&channel_ptr->channel);
}

// Receive and parse one SPsec message; timeout=0 means non-blocking.
SPsecMessage *participant_channel_receive(SPsecCommChannel *channel_ptr,
                                          int timeout) {
  if (!channel_ptr || channel_ptr->channel.socket < 0) {
    LOG_ERROR(logger_name_ptr, "Invalid channel or socket");
    return NULL;
  }

  // Transport is handled by the platform CAN layer, yielding a portable CanFrame.
  CanFrame frame = {0};
  signed char got = can_channel_receive_frame(&channel_ptr->channel, &frame, timeout);
  if (got < 0) {
    if (can_channel_check_link_alive(&channel_ptr->channel) < 0 &&
        can_channel_recover(&channel_ptr->channel) == 0) {
      LOG_INFO(logger_name_ptr, "Recovered CAN channel on link bounce");
      got = can_channel_receive_frame(&channel_ptr->channel, &frame, timeout);
    }
  }
  if (got <= 0) return NULL;

  uint32_t base_id = frame.can_id; // already 29-bit masked
  uint8_t *arb_id_bytes_ptr = (uint8_t *)&base_id;

  LOG_DEBUG(logger_name_ptr,
            "Received arb_id: %08x len: %d, participant_id: %u",
            (unsigned)base_id, frame.len, channel_ptr->participant_id);

  return can_protocol_parse_received_frame(base_id, arb_id_bytes_ptr, &frame);
}

// Send AppData over the insecure channel.
signed char participant_send_insecure_channel_message(CommChannel *channel_ptr,
                                                      AppData *msg_ptr) {
  LOG_INFO(logger_name_ptr, "Sending insecure message with ID: %08x", msg_ptr->address);
  char hex_data[9];
  format_hex_string(hex_data, sizeof(hex_data), msg_ptr->data_ptr,
                    msg_ptr->data_len < 4 ? msg_ptr->data_len : 4);
  LOG_DEBUG(logger_name_ptr, "Sending insecure message with data: %s... (len=%zu)",
            hex_data, msg_ptr->data_len);
  return channel_send_appdata(channel_ptr, msg_ptr);
}
