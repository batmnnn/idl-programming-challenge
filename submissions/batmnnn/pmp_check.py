#!/usr/bin/env python3
import sys

def count_trailing_ones(x):
    """
    Counts the number of consecutive 1 bits starting from the least significant bit.
    This is used for computing the size of a NAPOT region.
    """
    count = 0
    while x & 1:
        count += 1
        x >>= 1
    return count

class PMPRegion:
    def __init__(self, index, cfg, addr, all_pmpaddr):
        """
        Initializes a PMP region.
          - index: the region index (0..63)
          - cfg: the 8-bit PMP configuration (as an integer)
          - addr: the corresponding PMP address register value (as an integer)
          - all_pmpaddr: the full list of PMP address registers (needed for TOR mode)
          
        The configuration register is assumed to be laid out as follows:
          Bit 7: Lock (L)
          Bits 6-5: Address-matching mode (A):
                   0 = OFF (disabled)
                   1 = TOR (top of range)
                   2 = NA4 (naturally aligned 4‑byte region)
                   3 = NAPOT (naturally aligned power‑of‑two region)
          Bit 4: Execute permission (X)
          Bit 3: Write permission (W)
          Bit 2: Read permission (R)
          Bits 1-0: Unused
        """
        self.index = index
        self.cfg = cfg
        self.addr = addr
        self.all_pmpaddr = all_pmpaddr
        
        self.L = (cfg >> 7) & 0x1        # Lock bit
        self.a = (cfg >> 5) & 0x3        # Address matching mode (0=OFF,1=TOR,2=NA4,3=NAPOT)
        self.X = (cfg >> 4) & 0x1        # Execute permission
        self.W = (cfg >> 3) & 0x1        # Write permission
        self.R = (cfg >> 2) & 0x1        # Read permission

    def region_bounds(self):
        """
        Computes the region boundaries (as a tuple: (lower, upper)) for this PMP entry.
          - For TOR (a==1): region = [ (prev_pmpaddr << 2) or 0, (this pmpaddr << 2) )
          - For NA4 (a==2): region = [ (pmpaddr << 2), (pmpaddr << 2) + 4 )
          - For NAPOT (a==3): let n be the number of trailing ones in the pmpaddr;
                             region size = 2^(n+3) bytes and region base = (pmpaddr with its lower n bits cleared) << 2.
        If the PMP entry is disabled (a==0) the function returns (None, None).
        """
        if self.a == 0:
            return None, None  # Entry disabled; no region.
        if self.a == 1:  # TOR mode
            lower = 0 if self.index == 0 else (self.all_pmpaddr[self.index - 1] << 2)
            upper = self.addr << 2
            return lower, upper
        elif self.a == 2:  # NA4 mode: exactly 4 bytes.
            lower = self.addr << 2
            upper = lower + 4
            return lower, upper
        elif self.a == 3:  # NAPOT mode.
            n = count_trailing_ones(self.addr)
            size = 1 << (n + 3)  # Size in bytes.
            # Clear the lower n bits and shift left by 2 (since PMP addresses are shifted)
            lower = (self.addr & ~((1 << n) - 1)) << 2
            upper = lower + size
            return lower, upper
        else:
            return None, None

    def matches(self, phys_addr):
        """
        Returns True if the provided physical address falls within the region defined by this PMP entry.
        """
        lower, upper = self.region_bounds()
        if lower is None or upper is None:
            return False
        return lower <= phys_addr < upper

    def permits(self, op, priv_mode):
        """
        Checks whether this PMP entry allows the given operation.
          - op is one of 'R', 'W', 'X'
          - For supervisor (S) and user (U) modes, the permission bit must be set.
          - For machine (M) mode, if the entry is not locked, the access is allowed regardless.
        (The check for bypassing PMP in M-mode is handled outside this method.)
        """
        if op == 'R' and self.R:
            return True
        if op == 'W' and self.W:
            return True
        if op == 'X' and self.X:
            return True
        return False

def main():
    # Parse command-line arguments.
    if len(sys.argv) != 5:
        print("Usage: python3 pmp_check.py pmp_config.txt 0xaddress M/S/U R/W/X")
        sys.exit(1)

    config_file = sys.argv[1]
    address_str = sys.argv[2]
    mode = sys.argv[3].upper()
    operation = sys.argv[4].upper()

    # Validate physical address format.
    if not address_str.startswith("0x"):
        print("Invalid address format. Must start with '0x'.")
        sys.exit(1)
    try:
        phys_addr = int(address_str, 16)
    except ValueError:
        print("Invalid address value.")
        sys.exit(1)

    # Validate privilege mode and operation.
    if mode not in ['M', 'S', 'U']:
        print("Invalid privilege mode. Must be one of 'M', 'S', or 'U'.")
        sys.exit(1)
    if operation not in ['R', 'W', 'X']:
        print("Invalid operation. Must be one of 'R', 'W', or 'X'.")
        sys.exit(1)

    # For our simulation, we note that PMP rules are defined only in machine mode.
    # For S and U modes, if at least one PMP entry is implemented (A != 0), then an access that doesn't match any region faults.
    try:
        with open(config_file, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
            if len(lines) != 128:
                print("Configuration file must have exactly 128 non-empty lines.")
                sys.exit(1)
            pmpcfg = [int(line, 16) for line in lines[:64]]
            pmpaddr = [int(line, 16) for line in lines[64:]]
    except Exception as e:
        print(f"Error reading configuration file: {e}")
        sys.exit(1)

    # Build PMPRegion objects for each of the 64 PMP entries.
    regions = [PMPRegion(i, pmpcfg[i], pmpaddr[i], pmpaddr) for i in range(64)]

    # Determine whether any PMP entry is implemented (i.e. A field != 0).
    any_pmp = any(((cfg >> 5) & 0x3) != 0 for cfg in pmpcfg)

    # Check each PMP entry in order (lowest index first)
    for region in regions:
        if region.matches(phys_addr):
            # In machine mode, if the matching entry is not locked, the access is allowed outright.
            if mode == 'M' and region.L == 0:
                print("Access allowed")
                return
            # Otherwise, check the permission bit for the requested operation.
            if region.permits(operation, mode):
                print("Access allowed")
            else:
                print("Access fault")
            return

    # No PMP entry matched.
    # For S/U modes, if any PMP is implemented, an unmatched access faults.
    if any_pmp and mode in ('S', 'U'):
        print("Access fault")
    else:
        print("Access allowed")

if __name__ == "__main__":
    main()
