#include "api.h"
#include "params.h"
#include "randombytes.h"
#include "hal.h"
#include <libopencm3/stm32/gpio.h>
#include <string.h>

static void write_canary(unsigned char *d)
{
  *((uint64_t *)d) = 0x0123456789ABCDEF;
}

static int check_canary(unsigned char *d)
{
  if (*(uint64_t *)d != 0x0123456789ABCDEF)
    return -1;
  else
    return 0;
}

static int test_keys(void)
{
  unsigned char key_a[CRYPTO_BYTES + 16], key_b[CRYPTO_BYTES + 16];
  unsigned char pk[SABER_PUBLICKEYBYTES + 16];
  unsigned char sendb[SABER_CIPHERTEXTBYTES + 16];
  unsigned char sk_a[SABER_SECRETKEYBYTES + 16];
  unsigned char recv_byte_start;

  write_canary(key_a);
  write_canary(key_a + sizeof(key_a) - 8);
  write_canary(key_b);
  write_canary(key_b + sizeof(key_b) - 8);
  write_canary(pk);
  write_canary(pk + sizeof(pk) - 8);
  write_canary(sendb);
  write_canary(sendb + sizeof(sendb) - 8);
  write_canary(sk_a);
  write_canary(sk_a + sizeof(sk_a) - 8);

  int count = 0;

  while (1)
  {
    recv_USART_bytes(&recv_byte_start, 1);
    if (recv_byte_start == 'K')
    {
      recv_USART_bytes(sendb + 8, 32);
      crypto_kem_keypair(pk + 8, sk_a + 8);
      hal_send_str("Z");
    }
    if (recv_byte_start == 'S')
    {
      recv_USART_bytes(sendb + 8, SABER_CIPHERTEXTBYTES);
      crypto_kem_dec(key_a + 8, sendb + 8, sk_a + 8);
      hal_send_str("Z");
    }
  }

  return 0;
}

int main(void)
{
  hal_setup(CLOCK_BENCHMARK);
  hal_send_str("init ok!");
  gpio_mode_setup(GPIOA, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, GPIO7);
  unsigned char recv_byte_start;

  test_keys();

  return 0;
}
