rule RoyalRoad_encode_in_RTF
{
    strings:
        $enc_hex_1 = "B0747746" nocase
        $enc_hex_2 = "B2A66DFF" nocase
        $enc_hex_3 = "F2A32072" nocase
        $enc_hex_4 = "B2A46EFF" nocase
        $enc_hex_5 = "B25A6F00" nocase
        $enc_hex_6 = "A9A46EFE" nocase
        $enc_hex_7 = "945FDAD8" nocase
        $enc_hex_8 = "95A2748E" nocase
        $enc_hex_9 = "4DA2EE67" nocase

        $RTF= "{\\rt"
        
    condition:
        $RTF at 0 and 1 of ($enc_hex_*)
}
