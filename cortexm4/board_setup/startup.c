/*
 * STM32F407 Startup and UART
 *
 * - UART: PA2 (TX), 115200 baud, 8N1
 * - printf() output redirected to UART
 * - 16 MHz HSI clock (no PLL setup)
 */

#include <stdint.h>

/* Memory addresses (from linker script) */
extern uint32_t _estack;
extern uint32_t _sdata, _edata, _etext;
extern uint32_t _sbss, _ebss;

extern int main(void);

void Default_Handler(void) { while(1); }

/* Interrupt handlers (weak aliases) */
void Reset_Handler(void);
void NMI_Handler(void)         __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void)   __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler(void)   __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void)    __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void)  __attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void)         __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void)      __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void)     __attribute__((weak, alias("Default_Handler")));

/* Vector table */
__attribute__((section(".isr_vector")))
uint32_t *isr_vectors[] = {
    (uint32_t *)&_estack,
    (uint32_t *)Reset_Handler,
    (uint32_t *)NMI_Handler,
    (uint32_t *)HardFault_Handler,
    (uint32_t *)MemManage_Handler,
    (uint32_t *)BusFault_Handler,
    (uint32_t *)UsageFault_Handler,
    0, 0, 0, 0,
    (uint32_t *)SVC_Handler,
    0, 0,
    (uint32_t *)PendSV_Handler,
    (uint32_t *)SysTick_Handler,
};

/* ========== UART Configuration ========== */

/* RCC registers */
#define RCC_BASE        0x40023800
#define RCC_AHB1ENR     (*(volatile uint32_t *)(RCC_BASE + 0x30))
#define RCC_APB1ENR     (*(volatile uint32_t *)(RCC_BASE + 0x40))

/* GPIOA registers */
#define GPIOA_BASE      0x40020000
#define GPIOA_MODER     (*(volatile uint32_t *)(GPIOA_BASE + 0x00))
#define GPIOA_AFRL      (*(volatile uint32_t *)(GPIOA_BASE + 0x20))

/* USART2 registers */
#define USART2_BASE     0x40004400
#define USART2_SR       (*(volatile uint32_t *)(USART2_BASE + 0x00))
#define USART2_DR       (*(volatile uint32_t *)(USART2_BASE + 0x04))
#define USART2_BRR      (*(volatile uint32_t *)(USART2_BASE + 0x08))
#define USART2_CR1      (*(volatile uint32_t *)(USART2_BASE + 0x0C))

/* Clock and baud rate */
#define SYSCLK_FREQ     16000000
#define BAUDRATE        115200

static void uart_init(void)
{
    /* Enable GPIOA and USART2 clocks */
    RCC_AHB1ENR |= (1 << 0);   /* GPIOA */
    RCC_APB1ENR |= (1 << 17);  /* USART2 */

    /* PA2 as AF7 (USART2_TX) */
    GPIOA_MODER &= ~(3 << 4);
    GPIOA_MODER |= (2 << 4);   /* Alternate function */
    GPIOA_AFRL &= ~(0xF << 8);
    GPIOA_AFRL |= (7 << 8);    /* AF7 = USART2 */

    /* Configure USART2: 115200 baud, 8N1 */
    USART2_BRR = SYSCLK_FREQ / BAUDRATE;
    USART2_CR1 = (1 << 13) | (1 << 3);  /* UE + TE */
}

static void uart_putc(char c)
{
    while (!(USART2_SR & (1 << 7)));  /* Wait for TXE */
    USART2_DR = c;
}

/* Redirect printf() to UART */
int _write(int fd, char *ptr, int len)
{
    (void)fd;
    for (int i = 0; i < len; i++) {
        if (ptr[i] == '\n') uart_putc('\r');
        uart_putc(ptr[i]);
    }
    return len;
}

/* ========== Newlib stubs ========== */

void *_sbrk(int incr)
{
    static char heap[4096];
    static char *heap_end = heap;
    char *prev = heap_end;
    heap_end += incr;
    return prev;
}

void _exit(int status) { (void)status; while(1); }
int _close(int fd) { (void)fd; return -1; }
int _fstat(int fd, void *st) { (void)fd; (void)st; return 0; }
int _isatty(int fd) { (void)fd; return 1; }
int _lseek(int fd, int ptr, int dir) { (void)fd; (void)ptr; (void)dir; return 0; }
int _read(int fd, char *ptr, int len) { (void)fd; (void)ptr; (void)len; return 0; }

/* ========== Reset Handler ========== */

void Reset_Handler(void)
{
    /* Copy .data from Flash to SRAM */
    uint32_t *src = &_etext;
    uint32_t *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;

    /* Zero .bss */
    dst = &_sbss;
    while (dst < &_ebss) *dst++ = 0;

    /* Initialize UART */
    uart_init();

    /* Call main */
    main();

    while(1);
}
