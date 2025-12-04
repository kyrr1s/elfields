rule Invalid_ELF_Header_Fields
{
    meta:
        description = "Detects ELF files with invalid header field values"
        author = "kyrr1s"

    strings:
        $elf_magic = { 7F 45 4C 46 }

        $valid_class_00 = { 00 }
        $valid_class_01 = { 01 }
        $valid_class_02 = { 02 }

        $valid_data_00 = { 00 }
        $valid_data_01 = { 01 }
        $valid_data_02 = { 02 }

        $valid_version_00 = { 00 }
        $valid_version_01 = { 01 }

        $zero_byte = { 00 }

        $valid_osabi_00 = { 00 }  // SYSV
        $valid_osabi_01 = { 01 }  // HPUX
        $valid_osabi_02 = { 02 }  // NetBSD
        $valid_osabi_03 = { 03 }  // Linux
        $valid_osabi_04 = { 04 }  // GNUHurd
        $valid_osabi_06 = { 06 }  // Solaris
        $valid_osabi_07 = { 07 }  // AIX
        $valid_osabi_08 = { 08 }  // IRIX
        $valid_osabi_09 = { 09 }  // FreeBSD
        $valid_osabi_0a = { 0A }  // Tru64
        $valid_osabi_0b = { 0B }  // NovellModesto
        $valid_osabi_0c = { 0C }  // OpenBSD
        $valid_osabi_0d = { 0D }  // OpenVMS
        $valid_osabi_0e = { 0E }  // NonStopKernel
        $valid_osabi_0f = { 0F }  // AROS
        $valid_osabi_10 = { 10 }  // FenixOS
        $valid_osabi_11 = { 11 }  // CloudABI
        $valid_osabi_12 = { 12 }  // OpenVOS
        $valid_osabi_40 = { 40 }  // ARM_EABI
        $valid_osabi_ff = { FF }  // STANDALONE

        $valid_shentsize_32 = { 28 00 }
        $valid_shentsize_64 = { 40 00 }

    condition:
        $elf_magic at 0

        and
        (
            not ($valid_class_00 at 4 or $valid_class_01 at 4 or $valid_class_02 at 4)

            or not ($valid_data_00 at 5 or $valid_data_01 at 5 or $valid_data_02 at 5)

            or not ($valid_version_00 at 6 or $valid_version_01 at 6)

            or not ($valid_osabi_00 at 7 or $valid_osabi_01 at 7 or $valid_osabi_02 at 7 or
                 $valid_osabi_03 at 7 or $valid_osabi_04 at 7 or $valid_osabi_06 at 7 or
                 $valid_osabi_07 at 7 or $valid_osabi_08 at 7 or $valid_osabi_09 at 7 or
                 $valid_osabi_0a at 7 or $valid_osabi_0b at 7 or $valid_osabi_0c at 7 or
                 $valid_osabi_0d at 7 or $valid_osabi_0e at 7 or $valid_osabi_0f at 7 or
                 $valid_osabi_10 at 7 or $valid_osabi_11 at 7 or $valid_osabi_12 at 7 or
                 $valid_osabi_40 at 7 or $valid_osabi_ff at 7)

            or not ($zero_byte at 8 and $zero_byte at 9 and $zero_byte at 10 and $zero_byte at 11
                    and $zero_byte at 12 and $zero_byte at 13 and $zero_byte at 14 and $zero_byte at 15)

            or ($valid_class_01 at 4 and not $valid_shentsize_32 at 58)
            or ($valid_class_02 at 4 and not $valid_shentsize_64 at 58)
        )
}