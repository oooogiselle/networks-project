/*=============================================================================
 * File Name:   test_tun_io.c
 * Author:      Eva Tate and Giselle Wu
 * Course:      CS60: Computer Networks
 * Assignment:  Final Project: Userspace Stateful Firewall (Tunwall)
 * Date:        November 15, 2026
 *
 * Description: Tests for the failure paths of tun_open() that need no root
 *              (bad names, a device that does not exist, a device that is not
 *              a tun device). Attaching to a real tun device needs root and
 *              the namespace setup, so that path is covered by the
 *              integration tests (tests/integration/run_all.sh). Linux only.
 =============================================================================*/

#include <string.h>

#include "testutil.h"
#include "tun_io.h"

static void test_bad_names_are_rejected(void)
{
    char err[128] = "";
    CHECK(tun_open(NULL, err, sizeof err) == -1);
    CHECK(strstr(err, "bad tun device name") != NULL);
    err[0] = '\0';
    CHECK(tun_open("", err, sizeof err) == -1);
    CHECK(strstr(err, "bad tun device name") != NULL);
    err[0] = '\0';
    CHECK(tun_open("this-name-is-too-long", err, sizeof err) == -1);   /* >= IFNAMSIZ */
    CHECK(strstr(err, "bad tun device name") != NULL);
    CHECK(tun_open("x", NULL, 0) == -1);                               /* no buffer: still safe */
}

static void test_a_missing_device_is_refused_with_a_hint(void)
{
    /* Creating it on the fly would give a device with no routes: the firewall
     * would start and quietly pass nothing. Better to say what to do. */
    char err[256] = "";
    CHECK(tun_open("twnope0", err, sizeof err) == -1);
    CHECK(strstr(err, "twnope0") != NULL);
    CHECK(strstr(err, "no such device") != NULL);
    CHECK(strstr(err, "scripts/netns.sh") != NULL);
}

static void test_an_existing_device_that_is_not_a_tun_device_is_refused(void)
{
    /* "lo" exists in every namespace but is not a tun device, so attaching
     * must fail (or /dev/net/tun must be unavailable); never succeed. */
    char err[256] = "";
    CHECK(tun_open("lo", err, sizeof err) == -1);
    CHECK(strstr(err, "lo:") == err);
    CHECK(strstr(err, "cannot attach") != NULL || strstr(err, "cannot open /dev/net/tun") != NULL);
}

int main(void)
{
    RUN(test_bad_names_are_rejected);
    RUN(test_a_missing_device_is_refused_with_a_hint);
    RUN(test_an_existing_device_that_is_not_a_tun_device_is_refused);
    TEST_DONE();
}
