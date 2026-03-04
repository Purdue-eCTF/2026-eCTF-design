MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 256K
  /* TODO: determine how to use ECC ram without hardfaulting */
  RAM : ORIGIN = 0x20200000, LENGTH = 32K
}
