use bytemuck::{Pod, Zeroable, cast_ref};
use argon2::{Argon2, Algorithm, Version, Params};
use argon2::Block;
use core::mem::MaybeUninit;

use mspm0l222x_hal::{
    flash::FlashController,
    trng::Trng,
};

// ARGON2 TUNING PARAMETERS
// Requirements: Boot ~4s and PIN ~1s

// PLACEHOLDER: Memory cost in KB
// MSPM0L2228 has 32KB RAM keep low (1KB) to prevent stack overflow
pub const ARGON_M_COST: u32 = 8;
const ARGON_M_COST_USIZE: usize = ARGON_M_COST as usize;

static mut ARGON_MEM: [Block; ARGON_M_COST_USIZE] =
    unsafe { MaybeUninit::zeroed().assume_init() };

#[inline(always)]
fn argon_mem() -> &'static mut [Block; ARGON_M_COST_USIZE] {
    unsafe { &mut *(&raw mut ARGON_MEM) }
}

// Parallelism: single thread for embedded
pub const ARGON_P_COST: u32 = 1;

// PLACEHOLDER: Time cost (iterations) for Boot Salt 1 generation
// MUST be tuned on hardware to hit ~4 seconds
pub const T_COST_BOOT: u32 = 1; 

// Time cost for PIN Salt derivation
// MUST be tuned on hardware to hit ~1 second
pub const T_COST_PIN: u32 = 1;


// FLASH MEMORY LAYOUT
pub const SALT_PAGE_ADDR: u32 = 0x0003_A400; //Is this the correct addess? I cannot write here
//pub const SALT_PAGE_ADDR: u32 = 0x0003_F000; //temp address for testing
pub const FLASH_PAGE_SIZE: usize = 1024;

// Physical layout of the Security Page in Flash
// Size must be exactly 1024 bytes to match hardware sector erase size
// Stores Boot Salts and Lockout state
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SaltPage {
    // Boot Salt 0: Random 32 bytes (non-volatile)
    pub boot_salt_0: [u8; 32], 
    
    // Boot Salt 1: Derived from Salt 0 (volatile)
    // Erased during operations
    pub boot_salt_1: [u8; 32], 
    
    // Lockout Flag: Indicates "Operation in Progress"
    // 0xFFFFFFFF = Idle/Clean
    // 0x00000000 = Lockout Active
    pub lockout_flag: u32,

    // Padding to ensure structure matches full page size
    // 1024 - 32 - 32 - 4 = 956 bytes
    pub padding: [u8; FLASH_PAGE_SIZE - 68], 
}

unsafe impl Zeroable for SaltPage {}
unsafe impl Pod for SaltPage {}

const _: [(); FLASH_PAGE_SIZE] = [(); core::mem::size_of::<SaltPage>()];

/// Helper: Checks if a memory region is in erased state (0xFF)
pub fn is_erased(data: &[u8]) -> bool {
    data.iter().all(|&x| x == 0xFF)
}

impl SaltPage {
    // Returns a clean state for initialization
    pub fn new_empty() -> Self {
        Self {
            boot_salt_0: [0u8; 32],
            boot_salt_1: [0u8; 32],
            lockout_flag: 0xFFFFFFFF, // Flash erased state
            padding: [0u8; FLASH_PAGE_SIZE - 68],
        }
    }
}

// Handles atomic Flash operations for security state
pub struct FlashOps;

impl FlashOps {
    // Reads the Salt Page directly from memory-mapped Flash
    pub fn read() -> SaltPage {
        let ptr = SALT_PAGE_ADDR as *const SaltPage;
        unsafe { core::ptr::read_volatile(ptr) }
    }

    // This performs a sector erase (1KB) then writes
    pub fn write(flash: &FlashController, page: &SaltPage) {
        let bytes: &[u8; 1024] = cast_ref(page);
        
        unsafe {
            flash.write_unprotect(SALT_PAGE_ADDR, 1024);

            let _ = flash.rewrite_page(SALT_PAGE_ADDR, bytes); // for testing
            flash.write_protect(SALT_PAGE_ADDR, 1024);
        }
    }

    // LOCKOUT MECHANISM
    // 1. Reads current state
    // 2. Moves Salt 1 to RAM
    // 3. Wipes Salt 1 from buffer and sets lockout flag
    // 4. Writes to Flash (Physical Wipe)
    // Returns: The Salt 1 for RAM usage
    pub fn fetch_and_lock(flash: &FlashController) -> [u8; 32] {
        let mut page = Self::read();

        if page.lockout_flag == 0x00000000 {
             return page.boot_salt_1; 
        }
        
        // Move secret to RAM
        let secret_salt = page.boot_salt_1;

        // Logical Wipe & Lockout
        page.boot_salt_1 = [0u8; 32]; 
        page.lockout_flag = 0x00000000;

        // Physical Wipe
        Self::write(flash, &page);

        secret_salt
    }

    // Restores Salt 1 and clears Lockout flag after success
    pub fn restore_and_unlock(flash: &FlashController, salt_1: &[u8; 32]) {
        let mut page = Self::read();
        
        page.boot_salt_1 = *salt_1;
        page.lockout_flag = 0xFFFFFFFF; // Idle state

        Self::write(flash, &page);
    }
}

// Security Context: Manages the secure boot state machine
pub struct SecurityContext {
    // RAM cache for Salt 1 (since it's wiped from Flash during ops)
    pub ram_salt: [u8; 32],
}

impl SecurityContext {
    // Initialize a new context
    pub const fn new() -> Self {
        Self {
            ram_salt: [0u8; 32],
        }
    }

    // CORE BOOT LOGIC (Sec 5.1.1)
    // Uses the hardware TRNG and FlashController directly
    pub fn secure_boot(
        &mut self, 
        flash: &FlashController, 
        trng: &Trng
    ) -> [u8; 32] {
        let mut page = FlashOps::read();
        let mut dirty = false;
        let mut penalty_applied = false;

        // A. Validate Boot Salt 0 (Permanent)
        if is_erased(&page.boot_salt_0) {
            // Hardware TRNG
            // returning 4 bytes (u32)
            // We fill the 32-byte buffer by calling it 8 times
            for chunk in page.boot_salt_0.chunks_mut(4) {
                let r = trng.word();
                chunk.copy_from_slice(&r.to_le_bytes());
            }
            
            // Generate Salt 1 from Salt 0 (Implicit ~4s penalty)
            self.derive_argon(&page.boot_salt_0, &mut page.boot_salt_1, T_COST_BOOT);
            
            dirty = true;
            penalty_applied = true; 
        }

        // B. Handle Lockout/Integrity (Sec 5.1.1)
        // Check if Salt 1 is missing or if the lockout_flag was tripped (0x00)
        if is_erased(&page.boot_salt_1) || is_zero(&page.boot_salt_1) || page.lockout_flag == 0 {
            if !penalty_applied {
                // Enforce mandatory 4-second delay via Argon2id
                self.derive_argon(&page.boot_salt_0, &mut page.boot_salt_1, T_COST_BOOT);
                dirty = true;
            }
        }

        // C. Update Flash if we regenerated salts
        if dirty {
            FlashOps::write(flash, &page);
        }
        
        // D. LOCKOUT ENTRY: Move secret to RAM and WIPE Flash
        self.ram_salt = FlashOps::fetch_and_lock(flash);
        
        self.ram_salt
    }

    pub fn authenticate_pin(&self, pin_input: &[u8], pin_salt: &[u8; 32]) -> Result<[u8; 32], ()> {
        let mut k_auth = [0u8; 32];
        
        // Tuned to ~1 second delay
        let params = Params::new(ARGON_M_COST, T_COST_PIN, ARGON_P_COST, Some(32))
            .map_err(|_| ())?;
            
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        
        // Argon2id treats 'pin_input' as password and 'pin_salt' as salt
        // This effectively computes H(PIN||Salt)
        match argon.hash_password_into_with_memory(pin_input, pin_salt, &mut k_auth, argon_mem()) {
            Ok(_) => Ok(k_auth),
            Err(_) => Err(()),
        }
    }
    
    // PIN SALT GENERATION
    // Derives PIN Salt from Boot Salt 1
    // MUST take ~1 second
    pub fn generate_pin_salt(&self, boot_salt_1: &[u8; 32]) -> [u8; 32] {
        let mut pin_salt = [0u8; 32];
        // T_COST_PIN is tuned for 1s delay
        self.derive_argon(boot_salt_1, &mut pin_salt, T_COST_PIN);
        pin_salt
    }
    
    // Helper: Argon2id derivation
    pub fn derive_argon(&self, input: &[u8], output: &mut [u8], t_cost: u32) {
        const DERIVE_SALT: &[u8] = b"ectf-deriv";

        let params = Params::new(ARGON_M_COST, t_cost, ARGON_P_COST, Some(output.len()))
        .expect("Argon Params Invalid");
            
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                
        argon
        .hash_password_into_with_memory(input, DERIVE_SALT, output, argon_mem())
        .expect("Argon Derivation Failed");
    }
}

// Helper for checking zeroed memory
fn is_zero(data: &[u8]) -> bool {
    data.iter().all(|&x| x == 0x00)
}