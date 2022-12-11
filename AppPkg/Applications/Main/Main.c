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
#include <Library/UefiLib.h>
/*
#include <Library/UefiApplicationEntryPoint.h>
*/
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
/*
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
*/
{

  AsciiPrint("Hello there fellow Programmer.\r\n");
  AsciiPrint("Welcome to the world of EDK II.\r\n");

  int ret;
  struct sockaddr_in local_addr;
  struct sockaddr_in remote_addr;
  int s;

  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == -1) {
    AsciiPrint("ERROR - socket error\r\n");
    return 1;
  }

  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sin_len = sizeof(local_addr);
  local_addr.sin_family = AF_INET;

  ret = bind(s, (struct sockaddr *)&local_addr, sizeof(local_addr));
  if (ret == -1) {
    AsciiPrint("ERROR - bind error\r\n");
    return 1;
  }

  memset(&remote_addr, 0, sizeof(remote_addr));
  remote_addr.sin_len = sizeof(remote_addr);
  remote_addr.sin_family = AF_INET;
  remote_addr.sin_addr.s_addr = 192 | 168 << 8 | 17 << 16 | 2 << 24;
  remote_addr.sin_port = htons(8443);

  ret = connect(s, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
  if (ret == -1) {
    AsciiPrint("ERROR - connect error\r\n");
    return 1;
  }

  ptls_key_exchange_algorithm_t *client_keyex[] = {&ptls_minicrypto_x25519, NULL};
  ptls_context_t client_ctx = {ptls_minicrypto_random_bytes, &ptls_get_time, client_keyex, ptls_minicrypto_cipher_suites};
  ptls_t *client = NULL;
  ptls_buffer_t cbuf;
  uint8_t cbuf_small[16384];
  uint8_t recvbuf[8192];
  ssize_t roff, soff, rret, sret;

  AsciiPrint("ptls_new\r\n");
  client = ptls_new(&client_ctx, 0);
  AsciiPrint("after ptls_new\r\n");
  ptls_buffer_init(&cbuf, cbuf_small, sizeof(cbuf_small));
  AsciiPrint("after ptls_buffer_init\r\n");

  ret = ptls_handshake(client, &cbuf, NULL, NULL, NULL);
  AsciiPrint("ptls_handshake ret=%d\r\n", ret);
  AsciiPrint("ptls_handshake emit %d bytes\r\n", cbuf.off);

  soff = 0;
  do {
    sret = send(s, cbuf.base + soff, cbuf.off - soff, 0);
    AsciiPrint("send bytes %d\r\n", sret);
    if (sret < 0) {
      return 1;
    }
    soff += sret;
  } while (cbuf.off != soff);
  ptls_buffer_dispose(&cbuf);

  do {
    rret = recv(s, recvbuf, sizeof(recvbuf), 0);
    AsciiPrint("recv bytes %d\r\n", rret);
    roff = 0;
    do {
      ptls_buffer_init(&cbuf, cbuf_small, sizeof(cbuf_small));
      size_t consumed = rret - roff;
      AsciiPrint("supply %d bytes into ptls_handshake\r\n", consumed);
      ret = ptls_handshake(client, &cbuf, recvbuf + roff, &consumed, NULL);
      AsciiPrint("ptls_handshake consume %d bytes, emit %d bytes\r\n", consumed, cbuf.off);
      roff += consumed;
      if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && cbuf.off != 0) {
        soff = 0;
        do {
          sret = send(s, cbuf.base + soff, cbuf.off - soff, 0);
          AsciiPrint("send bytes %d\r\n", sret);
          if (sret < 0) {
            return 1;
          }
          soff += sret;
        } while (cbuf.off != soff);
      }
      ptls_buffer_dispose(&cbuf);
    } while (ret == PTLS_ERROR_IN_PROGRESS && rret != roff);
  } while (ret == PTLS_ERROR_IN_PROGRESS);

  if (ret == 0) {
    AsciiPrint("handshake succeeded\r\n");
  }

  ptls_buffer_t plaintextbuf;
  while (roff < rret) {
    ptls_buffer_init(&plaintextbuf, "", 0);
    size_t consumed = rret - roff;
    ret = ptls_receive(client, &plaintextbuf, recvbuf + roff, &consumed);
    AsciiPrint("ptls_receive consume %d bytes\r\n", consumed);
    roff += consumed;
    AsciiPrint("plaintextbuf %d bytes\r\n", plaintextbuf.off);
    ptls_buffer_dispose(&plaintextbuf);
  }
  ptls_buffer_init(&cbuf, cbuf_small, sizeof(cbuf_small));
  ret = ptls_send(client, &cbuf, "Hello", sizeof("Hello"));
  AsciiPrint("ptls_send return %d\r\n", ret);
  AsciiPrint("ptls_send emit %d bytes\r\n", cbuf.off);

  soff = 0;
  do {
    sret = send(s, cbuf.base + soff, cbuf.off - soff, 0);
    AsciiPrint("send bytes %d\r\n", sret);
    if (sret < 0) {
      return 1;
    }
    soff += sret;
  } while (cbuf.off != soff);
  ptls_buffer_dispose(&cbuf);

  rret = recv(s, recvbuf, sizeof(recvbuf), 0);
  if (rret <= 0) {
    return 1;
  }
  AsciiPrint("recv bytes %d\r\n", rret);  
  roff = 0;
  while (roff < rret) {
    ptls_buffer_init(&plaintextbuf, "", 0);
    size_t consumed = rret - roff;
    ret = ptls_receive(client, &plaintextbuf, recvbuf + roff, &consumed);
    AsciiPrint("ptls_receive consume %d bytes\r\n", consumed);
    roff += consumed;
    AsciiPrint("plaintextbuf %d bytes\r\n", plaintextbuf.off);
    ptls_buffer_dispose(&plaintextbuf);
  }

  return 0;
}
