rule XFiles
{
    meta:
        author = "MalBeacon"
        description = "XFiles system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "Operation ID:" ascii
        $x2 = "Operating System:" ascii
        $x3 = "Screens:" ascii
        $x4 = "Desktop Screenshot Taken:" ascii
        $x5 = "Windows Processes" ascii

    condition:
        all of them
}