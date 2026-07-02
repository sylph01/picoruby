/* Raspi SDK */
#include <pico/stdlib.h>
#include <pico/bootrom.h>
#include <pico/critical_section.h>
#include <bsp/board.h>
#include <tusb.h>
#include <hardware/clocks.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>

/* PicoRuby */
#include "picoruby.h"
#include "picoruby/debug.h"
#include "hal.h" // in picoruby-machine
#include "main_task.c"

#if defined(PICORB_VM_MRUBY) && defined(PICORB_ALLOC_ESTALLOC)
#include "../../picoruby-mruby/include/alloc.h"
static critical_section_t heap_critsec;

static void
heap_enter_critical(void)
{
  critical_section_enter_blocking(&heap_critsec);
}

static void
heap_exit_critical(void)
{
  critical_section_exit(&heap_critsec);
}
#endif

#if !defined(HEAP_SIZE)
  #if defined(PICO_RP2040)
    #define RAM_SIZE_KB         264
    #define WIFI_STACK_SIZE_KB   32
  #elif defined(PICO_RP2350)
    #define RAM_SIZE_KB         524
    #define WIFI_STACK_SIZE_KB   80
  #else
    #error "PICO_RP2040 or PICO_RP2350 must be defined"
  #endif
  // Compiling a big Ruby code may need more stack size
  #define BASIC_STACK_SIZE_KB   80
  #if defined(USE_WIFI)
    #define STACK_SIZE_KB (BASIC_STACK_SIZE_KB + WIFI_STACK_SIZE_KB)
  #else
    #define STACK_SIZE_KB BASIC_STACK_SIZE_KB
  #endif
  #define HEAP_SIZE_KB (RAM_SIZE_KB - STACK_SIZE_KB)
  #define HEAP_SIZE (HEAP_SIZE_KB * 1024)
#endif

#if defined(R2P2_ALLOC_LIBC)
  #define heap_pool NULL
#else
  static uint8_t heap_pool[HEAP_SIZE] __attribute__((aligned(8)));
#endif

#if defined(PICORB_VM_MRUBY)
  extern mrb_state *global_mrb; /* defined in mruby-compiler (ccontext.c) */
#endif

/* Linker symbol: bottom of C stack (top of heap region) */
extern uint8_t __StackBottom[];

static void
gpio_set_in_pull_up(uint pin)
{
  gpio_init(pin);
  gpio_set_dir(pin, GPIO_IN);
  gpio_pull_up(pin);
}

static void
gpio_set_in_pull_down(uint pin)
{
  gpio_init(pin);
  gpio_set_dir(pin, GPIO_IN);
  gpio_pull_down(pin);
}

// All GPIOs will be input to maximize safety for
// possible peripheral for PicoRuby official Board (PRB)
static void
gpio_init_safe(void)
{
#if !defined(PICORB_DEBUG)
  // --- UART ---
  // GPIO0: UART_TX
  gpio_set_in_pull_up(0);
  gpio_set_in_pull_up(1);
#endif

  // --- SPI (2-5) ---
  for (int pin = 2; pin <= 4; pin++) {
    gpio_set_in_pull_down(pin);
  }
  gpio_set_in_pull_up(5); // CS: Unselect

  // --- I2C (6-7, 8-9) ---
  // IN & PULLUP: emulate open-drain output
  for (int pin = 6; pin <= 9; pin++) {
    gpio_set_in_pull_up(pin);
  }

  // --- PWM * 2 (10-11) ---
  gpio_set_in_pull_down(10);
  gpio_set_in_pull_down(11);

  // --- DAC (12-15) ---
  for (int pin = 12; pin <= 15; pin++) {
    gpio_set_in_pull_down(pin);
  }

  // --- LED (16) ---
  gpio_set_in_pull_down(16);

  // --- SWITCH, ENCODER, ADC (17-29) ---
  for (int pin = 17; pin <= 29; pin++) {
    gpio_set_in_pull_down(pin);
  }
}

#if defined(R2P2_TRUSTZONE)
/* Report the boot-exception class over the LED (GPIO25), since USB CDC is
 * unreliable during NS bring-up. Blinks a 32-bit word as 8 hex nibbles,
 * MSB first; value 0 = one long pulse. Slow and countable. */
static void tz_busy(uint32_t loops) {
  for (volatile uint32_t i = 0; i < loops; i++) __asm volatile ("nop");
}
#define TZ_MS(n) ((n) * 25000u)  /* ~n ms at 150 MHz */
static void tz_nibble(unsigned v) {
  if (v == 0) { gpio_put(25, 1); tz_busy(TZ_MS(1400)); gpio_put(25, 0); }
  else for (unsigned i = 0; i < v; i++) {
    gpio_put(25, 1); tz_busy(TZ_MS(350));
    gpio_put(25, 0); tz_busy(TZ_MS(350));
  }
  tz_busy(TZ_MS(2200));
}
static void __attribute__((noreturn)) tz_blink_word(uint32_t w) {
  gpio_init(25); gpio_set_dir(25, GPIO_OUT);
  for (;;) {
    for (int s = 28; s >= 0; s -= 4) tz_nibble((w >> s) & 0xfu);
    tz_busy(TZ_MS(5000));
  }
}
#endif

int
main(void)
{
  stdio_init_all();
  // printf() goes to Picoprobe UART
  printf("R2P2 PicoRuby starting...\n");
  printf("Heap size: %d KB\n", HEAP_SIZE_KB);
  board_init();

  gpio_init_safe();

#if !defined(R2P2_ALLOC_LIBC)
  assert((uint8_t *)heap_pool + HEAP_SIZE <= (uint8_t *)__StackBottom
         && "heap_pool overlaps with C stack");
#endif

  int ret = 0;

#if defined(PICORB_VM_MRUBY)
  mrb_state *mrb = mrb_open_with_custom_alloc(heap_pool, HEAP_SIZE);
#if defined(PICORB_ALLOC_ESTALLOC)
  critical_section_init(&heap_critsec);
  mrb_alloc_set_critical_section(heap_enter_critical, heap_exit_critical);
#endif
  global_mrb = mrb;
  mrc_irep *irep = mrb_read_irep(mrb, main_task);
  mrc_ccontext *cc = mrc_ccontext_new(mrb);
  mrb_value name = mrb_str_new_lit(mrb, "R2P2");
  mrb_value task = mrc_create_task(cc, irep, name, mrb_nil_value(), mrb_obj_value(mrb->top_self));
  if (mrb_nil_p(task)) {
    const char *msg = "mrbc_create_task failed\n";
    picorb_hal_write(1, msg, strlen(msg));
    ret = 1;
  }
  else {
    mrb_task_run(mrb);
  }
#if defined(R2P2_TRUSTZONE)
  /* TZ bring-up: mrb_task_run returned, so the boot task raised or the
   * scheduler ended. The VM would normally stop servicing USB and the port
   * would never come up. Instead, keep USB alive here so the CDC port
   * enumerates, and print the boot error once the host attaches (DTR). This
   * turns the dead-end into a readable console. Remove once boot is clean. */
  {
    /* USB CDC has been unreadable in NS bring-up, so report the boot
     * outcome over the LED instead: blink the first 4 chars of the
     * exception class name as hex (e.g. "Runt"=0x52756E74 -> RuntimeError,
     * "Load"=0x4C6F6164 -> LoadError, "Argu"->ArgumentError, "NoMe"/"Name",
     * "Type", ...), or "NONE"=0x4E4F4E45 if the VM exited with no exception
     * (clean scheduler end). */
    irq_set_enabled(USBCTRL_IRQ, false);
    uint32_t code;
    if (mrb->exc) {
      const char *cls = mrb_obj_classname(mrb, mrb_obj_value(mrb->exc));
      code = 0;
      for (int i = 0; i < 4 && cls[i]; i++) code = (code << 8) | (uint8_t)cls[i];
    } else {
      code = 0x4E4F4E45u; /* "NONE" */
    }
    tz_blink_word(code); /* never returns */
  }
#endif
  if (mrb->exc) {
    mrb_print_error(mrb);
    ret = 1;
  }
  mrb_close(mrb);
  mrc_ccontext_free(cc);
#elif defined(PICORB_VM_MRUBYC)
  mrbc_init(heap_pool, HEAP_SIZE);
  mrbc_tcb *main_tcb = mrbc_create_task(main_task, 0);
  if (!main_tcb) {
    const char *msg = "mrbc_create_task failed\n";
    picorb_hal_write(1, msg, strlen(msg));
    ret = 1;
  }
  else {
    mrbc_set_task_name(main_tcb, "main_task");
    mrbc_vm *vm = &main_tcb->vm;
    picoruby_init_require(vm);
    mrbc_run();
  }
#endif
  return ret;
}
