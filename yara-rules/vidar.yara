rule Vidar
{
    meta:
        author = "RussianPanda"
        description = "Detects Vidar Stealer"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar"
    
    strings:
        $x1 = "Work Dir: In memory" ascii
        $x2 = "information.txt" ascii
        $x3 = "Soft\\Steam\\steam_tokens.txt" ascii
        $x4 = "N0ZWFt" ascii
    
    condition:
        uint16(0) == 0x5A4D and all of them
}
