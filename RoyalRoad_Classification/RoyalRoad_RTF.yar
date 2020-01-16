
rule RoyalRoad_RTF
{
    strings:
        $S1= "objw2180\\objh300" ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_RTF_v7
{
    strings:
        $v7_1= "{\\object\\objocx{\\objdata" ascii
        $v7_2= "ods0000"  ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and all of ($v7*) 
}