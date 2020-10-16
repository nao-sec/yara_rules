rule RoyalRoad_encode_in_RTF
{
    strings:
        $enc_hex_1 = "B0747746" nocase
        $enc_hex_2 = "B2A66DFF" nocase
        $enc_hex_3 = "F2A32072" nocase
        $enc_hex_4 = "B2A46EFF" nocase
        $enc_hex_5 = "B25A6F00" nocase
        $enc_hex_6 = "A9A46EFE" nocase

        $RTF= "{\\rt"
        
    condition:
        $RTF at 0 and 1 of ($enc_hex_*)
}
