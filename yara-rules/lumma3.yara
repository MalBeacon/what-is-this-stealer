rule Lumma2
{
    meta:
        author = "Davide Ciacciolo
        description = "Lumma3 system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "LummaC2, Build" ascii
        $x2 = "LID (Lumma ID):" ascii
        $x3 = "- ComputerNameDnsHostname:" ascii
        $x4 = "- ComputerNameNetBIOS:" ascii
        $x5 = "- Physical Installed Memory:" ascii

    condition:
        all of them
}