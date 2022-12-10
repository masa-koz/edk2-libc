/** @file
    A simple, basic, application showing how the Hello application could be
    built using the "Standard C Libraries" from StdLib.

    Copyright (c) 2010 - 2011, Intel Corporation. All rights reserved.<BR>
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/
//#include  <Uefi.h>
//#include  <Library/UefiLib.h>
//#include  <Library/ShellCEntryLib.h>

#include  <stdio.h>
#include "picotls.h"
#include "picotls/minicrypto.h"

#include <Uefi.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>

#include <sys/EfiSysCall.h>
#include <sys/endian.h>
#include <sys/socket.h>
/***
  Demonstrates basic workings of the main() function by displaying a
  welcoming message.

  Note that the UEFI command line is composed of 16-bit UCS2 wide characters.
  The easiest way to access the command line parameters is to cast Argv as:
      wchar_t **wArgv = (wchar_t **)Argv;

  @param[in]  Argc    Number of argument tokens pointed to by Argv.
  @param[in]  Argv    Array of Argc pointers to command line tokens.

  @retval  0         The application exited normally.
  @retval  Other     An error occurred.
***/
int
main (
  IN int Argc,
  IN char **Argv
  )
{

  puts("Hello there fellow Programmer.");
  puts("Welcome to the world of EDK II.");

  ptls_key_exchange_algorithm_t *client_keyex[] = {&ptls_minicrypto_x25519, NULL};
  ptls_context_t client_ctx = {ptls_minicrypto_random_bytes, &ptls_get_time, client_keyex, ptls_minicrypto_cipher_suites};
  ptls_t *client = NULL;
  ptls_buffer_t cbuf;
  uint8_t cbuf_small[16384];
  int ret;

  client = ptls_new(&client_ctx, 0);
  ptls_buffer_init(&cbuf, cbuf_small, sizeof(cbuf_small));

  ret = ptls_handshake(client, &cbuf, NULL, NULL, NULL);
  assert(ret == PTLS_ERROR_IN_PROGRESS);

  return 0;
}
