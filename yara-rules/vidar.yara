rule Vidar
{
    meta:
        author = "RussianPanda"
        description = "Detects Vidar Stealer"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar"
        modified = "2025-03-21"
        modifier = "Davide Ciacciolo"
    
    strings:
        $x1 = "Country: " ascii
        $x2 = "MachineID: " ascii
        $x3 = "Work Dir: " ascii
        $x4 = "[Hardware]" ascii
        $x5 = "[Processes]" ascii
        $x6 = "[Software]" ascii
    
    condition:
        all of them
}
