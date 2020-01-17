
rule RoyalRoad_encode_in_RTF
{
    strings:
        $enc_hex_1 = "B0747746"
        $enc_hex_2 = "B2A66DFF"
        $enc_hex_3 = "F2A32072"
        $enc_hex_4 = "B2A46EFF"
        $enc_hex_1l = "b0747746"
        $enc_hex_2l = "b2a66Dff"
        $enc_hex_3l = "f2a32072"
        $enc_hex_4l = "b2a46eff"
        $RTF= "{\\rt"
    condition:
        $RTF at 0 and 1 of ($enc_hex*)
}