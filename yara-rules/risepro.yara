rule RisePro
{
    meta:
        author = "MalBeacon"
        description = "RisePro system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "Build: " ascii
        $x2 = "Version:" ascii
        $x3 = "MachineID:" ascii
        $x4 = "GUID:" ascii
        $x5 = "[Hardware]" ascii
        $x6 = "[Processes]" ascii

    condition:
        all of them
}