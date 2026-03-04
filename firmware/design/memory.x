MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 256K
  /* using ECC ram hardfaults b/c bootloader writes to non-ECC, so we aren't using ECC */
  RAM : ORIGIN = 0x20200000, LENGTH = 32K
}
