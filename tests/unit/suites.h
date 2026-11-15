/* suites.h - one declaration per unit test suite (tests/unit/test_<name>.c). */
#ifndef TUNWALL_SUITES_H
#define TUNWALL_SUITES_H

void suite_common(void);
void suite_packet(void);
/* Add as they are written:
 * void suite_rules(void);
 * void suite_flow(void);
 * void suite_tcp_fsm(void);
 * void suite_fw(void);
 */

#endif /* TUNWALL_SUITES_H */
