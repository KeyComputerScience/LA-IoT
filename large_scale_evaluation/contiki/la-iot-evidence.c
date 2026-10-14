/* SPDX-License-Identifier: Apache-2.0
 * Contiki-NG v4.8 evidence scaffold. Not compiled or executed.
 * This resource proves application execution only. It is not a cryptographic
 * endpoint, radio driver, reliable transfer implementation, or complete LA-IoT.
 */
#include "contiki.h"
#include "coap-engine.h"
#include "sys/energest.h"
#include "sys/node-id.h"
#include <inttypes.h>
#include <stdio.h>

#ifndef LA_IOT_BUILD_ID
#define LA_IOT_BUILD_ID "UNSET"
#endif
#ifndef LA_IOT_RUN_ID
#define LA_IOT_RUN_ID "UNSET"
#endif
#ifndef LA_IOT_RUN_SEED
#define LA_IOT_RUN_SEED 0
#endif
/* Set a fresh identifier after each boot/reset. Nodes append their node ID. */
#ifndef LA_IOT_CLOCK_DOMAIN
#define LA_IOT_CLOCK_DOMAIN "UNSET-BOOT"
#endif

PROCESS(la_iot_evidence_process, "LA-IoT execution evidence");
AUTOSTART_PROCESSES(&la_iot_evidence_process);

static unsigned long coap_get_count;

static void
evidence_get(coap_message_t *request, coap_message_t *response,
             uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  static const char body[] = "LA-IoT execution evidence; not an aggregate";
  (void)request;
  (void)buffer;
  (void)preferred_size;
  (void)offset;
  coap_get_count++;
  coap_set_header_content_format(response, TEXT_PLAIN);
  coap_set_payload(response, body, sizeof(body) - 1);
  printf("LAIOT_COAP node=%u count=%lu build=%s\n",
         node_id, coap_get_count, LA_IOT_BUILD_ID);
}

RESOURCE(evidence_resource, "title=\"LA-IoT evidence\";rt=\"evidence\"",
         evidence_get, NULL, NULL, NULL);

static void
print_energest_snapshot(void)
{
  energest_flush();
  printf("LAIOT_ENERGEST {\"run_id\":\"%s\",\"seed\":%lu,"
         "\"node_id\":\"%u\",\"clock_domain\":\"%s/node-%u\","
         "\"time_us\":%" PRIu64 ",\"ticks_per_second\":%lu,"
         "\"cpu\":%" PRIu64 ",\"lpm\":%" PRIu64
         ",\"tx\":%" PRIu64 ",\"listen\":%" PRIu64 ",\"deep\":%" PRIu64 "}\n",
         LA_IOT_RUN_ID, (unsigned long)LA_IOT_RUN_SEED,
         node_id, LA_IOT_CLOCK_DOMAIN, node_id,
         ((uint64_t)clock_time() * UINT64_C(1000000)) / CLOCK_SECOND,
         (unsigned long)ENERGEST_SECOND,
         (uint64_t)energest_type_time(ENERGEST_TYPE_CPU),
         (uint64_t)energest_type_time(ENERGEST_TYPE_LPM),
         (uint64_t)energest_type_time(ENERGEST_TYPE_TRANSMIT),
         (uint64_t)energest_type_time(ENERGEST_TYPE_LISTEN),
         (uint64_t)energest_type_time(ENERGEST_TYPE_DEEP_LPM));
}

PROCESS_THREAD(la_iot_evidence_process, ev, data)
{
  static struct etimer trace_timer;
  PROCESS_BEGIN();
  printf("LAIOT_BOOT node=%u build=%s run=%s seed=%lu clock=%s/node-%u "
         "clock_second=%lu energest_second=%lu\n",
         node_id, LA_IOT_BUILD_ID, LA_IOT_RUN_ID,
         (unsigned long)LA_IOT_RUN_SEED, LA_IOT_CLOCK_DOMAIN, node_id,
         (unsigned long)CLOCK_SECOND, (unsigned long)ENERGEST_SECOND);
  coap_activate_resource(&evidence_resource, "la-iot/evidence");
  print_energest_snapshot();
  etimer_set(&trace_timer, 10 * CLOCK_SECOND);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&trace_timer));
    print_energest_snapshot();
    etimer_reset(&trace_timer);
  }
  PROCESS_END();
}

