rule RoyalRoad_v1
{
    strings:
        $S1= {6F 62 6A 77 32 31 38 30 5C 6F 62 6A 68 33 30 30 7B 5C 2A 5C 6F 62 6A 63 6C 61 73 73 20 45 71 75 61 74 69 6F 6E 2E 33 7D 7B 5C 2A 5C 6F 62 6A 64 61 74 61 20 30 31 30 35 30 30 30 30 30 32 30 30 30 30 30 30 30 42 30 30 30 30 30 30 34 35 37 31 37 35 36 31 37 34 36 39 36 46 36 45 32 45 33 33 30 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_v2
{
    strings:
        $S1= {6F 62 6A 77 32 31 38 30 5C 6F 62 6A 68 33 30 30 7B 5C 6F 62 6A 64 61 74 61 20 35 35 34 35 36 37 7B 5C 2A 5C 6F 62 6A 64 61 74 61 20 30 31 30 35 30 30 30 30 30 32 30 30 30 30 30 30 30 42 30 30 30 30 30 30 34 35 37 31 37 35 36 31 37 34 36 39 36 46 36 45 32 45 33 33 30 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_v3
{
    strings:
        $S1= {6F 62 6A 77 32 31 38 30 5C 6F 62 6A 68 33 30 30 7B 5C 6F 62 6A 64 61 74 61 20 35 35 34 35 36 37 7B 7B 5C 2A 5C 6F 62 6A 64 61 74 61 20 31 33 38 39 45 36 31 34 30 32 30 30 30 30 30 30 30 42 30 30 30 30 30 30 34 35 37 31 37 35 36 31 37 34 36 39 36 46 36 45 32 45 33 33 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_v4
{
    strings:
        $S1= {6F 62 6A 77 32 31 38 30 5C 6F 62 6A 68 33 30 30 7B 5C 6F 62 6A 64 61 74 61 20 35 35 34 35 36 37 7B 5C 2A 5C 6F 62 6A 64 61 74 61 20 20 30 31 30 35 30 30 30 30 30 32 30 30 30 30 30 30 30 62 30 30 30 30 30 30 34 35 37 31 37 35 36 31 37 34 36 39 36 66 36 65 32 65 33 33 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_v5
{
    strings:
        $S1= {6F 62 6A 68 33 30 30 7B 5C 6F 62 6A 64 61 74 61 20 7B 5C 6F 62 6A 65 63 74 20 35 31 35 7D 34 5C 37 38 31 5C 27 65 35 36 5C 27 32 66 37 7B 5C 2A 5C 6F 62 6A 64 61 74 61 20 20 30 31 30 35 30 30 30 30 30 32 30 30 30 30 30 30 30 62 30 30 30 30 30 30 34 35 37 31 37 35 36 31 37 34 36 39 36 66 36 65 32 65 33 33 30 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_v6_a
{
    strings:
        $S1= {6F 62 6A 77 32 31 38 30 5C 6F 62 6A 68 33 30 30 7B 5C 6F 62 6A 64 61 74 61 20 7B 5C 6F 62 6A 65 63 74 5C 6F 62 6A 65 6D 62 20 35 31 35 7D 34 5C 37 38 31 5C 27 65 35 36 5C 27 32 66 37 7B 5C 2A 5C 6F 62 6A 64 61 74 61 20 20 30 31 30 35 30 30 30 30 30 32 30 30 30 30 30 30 30 62 30 30 30 30 30 30 34 35 37 31 37 35 36 31 37 34 36 39 36 66 36 65 32 65 33 33 30 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_v6_b
{
    strings:
        $S1= {6F 62 6A 77 32 33 38 31 5C 6F 62 6A 68 33 30 30 7B 5C 6F 62 6A 64 61 74 61 5C 72 69 30 20 7B 5C 6F 62 6A 65 63 74 5C 6F 62 6A 65 6D 62 20 31 35 33 65 37 61 35 7D 34 61 37 33 7B 5C 6F 62 6A 64 61 74 61 5C 75 63 30 20 20 30 31 30 35 30 30 30 30 30 32 30 30 30 30 30 30 30 62 30 30 30 30 30 30 34 35 37 31 37 35 36 31 37 34 36 39 36 66 36 65 32 65 33 33 30 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_v6_c
{
    strings:
        $S1= {6F 62 6A 77 32 31 38 30 5C 6F 62 6A 68 33 30 30 7B 5C 6F 62 6A 64 61 74 61 5C 75 63 30 20 7B 5C 6F 62 6A 65 63 74 5C 6F 62 6A 65 6D 62 20 35 33 31 65 37 35 7D 34 61 39 66 62 37 7B 5C 6F 62 6A 64 61 74 61 5C 75 63 30 20 20 30 31 30 35 30 30 30 30 30 32 30 30 30 30 30 30 30 62 30 30 30 30 30 30 34 35 37 31 37 35 36 31 37 34 36 39 36 66 36 65 32 65 33 33 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_v6_d
{
    strings:
        $S1= {6F 62 6A 77 32 31 38 30 5C 6F 62 6A 68 33 30 30 7B 5C 6F 62 6A 64 61 74 61 20 7B 5C 6F 62 6A 65 63 74 5C 6F 62 6A 65 6D 62 20 35 33 31 5C 27 65 37 35 7D 34 5C 27 61 39 66 62 37 7B 5C 6F 62 6A 64 61 74 61 20 20 30 31 30 35 30 30 30 30 30 32 30 30 30 30 30 30 30 62 30 30 30 30 30 30 34 35 37 31 37 35 36 31 37 34 36 39 36 66 36 65 32 65 33 33 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

/*
rule RoyalRoad_v6
{
    strings:
        $S1= {6F 62 6A 77 32 ?? 38 ?? 5C 6F 62 6A 68 33 30 30 7B 5C 6F 62 6A 64 61 74 61 [1-5] 7B 5C 6F 62 6A 65 63 74 5C 6F 62 6A 65 6D 62 20 [3-8] 7D 34 [0-18] 5C 6F 62 6A 64 61 74 61 [0-4] 20 20 30 31 30 35 30 30 30 30 30 32 30 30 30 30 30 30 30 62 30 30 30 30 30 30 34 35 37 31 37 35 36 31 37 34 36 39 36 66 36 65 32 65 33 33 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}*/

rule RoyalRoad_v7a
{
    strings:
        $S1= {7B 5C 6F 62 6A 65 63 74 5C 6F 62 6A 6F 63 78 7B 5C 6F 62 6A 64 61 74 61 20 20 5C 62 69 6C 20 35 39 62 36 33 35 63 31 7B 5C 2A 5C 6F 62 6A 64 61 74 61 20 7B 5C 6F 64 73 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 30 30 33 34 35 33 33 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_v7b
{
    strings:
        $S1= {7B 5C 72 65 73 75 6C 74 20 20 7D 7D 7B 5C 6F 62 6A 65 63 74 5C 6F 62 6A 6F 63 78 7B 5C 6F 62 6A 64 61 74 61 20 20 5C 62 69 6C 20 32 39 62 36 61 38 63 31 7B 5C 2A 5C 6F 62 6A 64 61 74 61 20 7B 5C 6F 64 73 30 30 30 30 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_v7c
{
    strings:
        $S1= {7B 5C 6F 62 6A 65 63 74 5C 6F 62 6A 6F 63 78 7B 5C 6F 62 6A 64 61 74 61 20 38 31 66 39 32 33 61 33 37 7B 5C 2A 5C 6F 62 6A 64 61 74 61 20 7B 5C 6F 64 73 30 30 30 30 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_v7d
{
    strings:
        $S1= {7B 5C 6F 62 6A 65 63 74 5C 6F 62 6A 6F 63 78 7B 5C 6F 62 6A 64 61 74 61 20 20 5C 70 61 72 37 33 35 32 31 20 37 31 63 64 38 61 36 35 34 32 31 64 7B 5C 2A 5C 6F 62 6A 64 61 74 61 20 7B 5C 6F 64 73 30 30 30 30 30 30 30 30 30 30 30 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_v7e
{
    strings:
        $S1= {7B 5C 6F 62 6A 65 63 74 5C 6F 62 6A 6C 69 6E 6B 5C 6F 62 6A 73 63 61 6C 65 79 39 38 7B 5C 6F 6C 65 63 6C 73 69 64 20 5C 27 37 62 30 30 30 32 31 37 30 30 2D 30 30 30 30 2D 30 30 30 30 2D 43 30 30 30 2D 30 30 30 30 30 30 30 30 30 30 34 36 5C 27 37 64 7D 7B 5C 2A 5C 6F 62 6A 64 61 74 61 20 7B 5C 6F 64 73 30 30 30 30 30}
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}
