rule RoyalRoad_code_pattern1
{
strings:
    $S1= "48905d006c9c5b0000000000030101030a0a01085a5ab844eb7112ba7856341231"
    $RTF= "{\\rt"
    
condition:
    $RTF at 0 and $S1 
}

rule RoyalRoad_code_pattern2
{
    strings:
        $S1= "653037396132353234666136336135356662636665" ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_code_pattern3
{
strings:
    $S1="4746424151515151505050500000000000584242eb0642424235353336204460606060606060606061616161616161616161616161616161"
    $RTF= "{\\rt"
    
condition:
    $RTF at 0 and $S1 

}

rule RoyalRoad_code_pattern4ab
{
    strings:
        $S1= "4746424151515151505050500000000000584242EB064242423535333620446060606060606060606161616161616}1616161616161616161" ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}

rule RoyalRoad_code_pattern4ce
{
    strings:
        $S1= "584242eb064242423535333620446060606060606060606161616161616161616161616}1616161" ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}



rule RoyalRoad_code_pattern4d
{
    strings:
        $S1= "584242eb06424242353533362044606060606060606060616161616161616161616}16161616161" ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1 
}