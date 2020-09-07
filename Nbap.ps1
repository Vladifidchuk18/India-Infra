<#


#>

#requires -version 2

[CmdletBinding(SupportsShouldProcess=$True)]
param (
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        $InputObject,
    [Parameter()]
        [string]$Arguments = "-sT -T3", # Set sane defaults for command string
    [Parameter()]
        [string]$Location = "nmap", # In case nmap is not in PATH
    [Parameter()]
        [string]$OutDir = $pwd, # Specify the directory nmap should output XML files to
    [Parameter()]
        [string]$CSV # Specify that imported text files are CSVs and specify which column to use as targets
    )

BEGIN {
    # Get current date/time
    $ScriptStart = Get-Date

    # Check if selected output folder exists, create if required
    if(-not(Resolve-Path $OutDir -ErrorAction SilentlyContinue -ErrorVariable _rperror)){
        Write-Verbose "OutDir $($outdir) not found, creating..."
        mkdir $_rperror[0].TargetObject | out-null
    }
    $OutDir = Resolve-Path $OutDir
    Write-Verbose "Set output directory to $($OutDir)"

    # Define function to correctly handle input object depending on object type
    function Process-Input($In) {

        # Get ObjectType of input
        $InputType = $In.GetType().FullName
        Write-Verbose "Object Type: $($InputType)"

        $out = @()

        switch($InputType){
                
            "System.String" {
                # Attempt to split comma-separated strIngs
                $Out = $In.Replace(" ", "").Split(",")
                Write-Verbose "Target(s) from command lIne: $($Out)"
                }
            "System.IO.FileInfo" {
                # Read hosts from file Into array
                if($CSV.Length -gt 0){
                    Import-CSV $in.FullName |%{
                        $out += $_.($CSV)
                    }
                }
                else {
                    $Out = Get-Content($In.FullName)
                    Write-Verbose "Target(s) from file $($In.FullName): $($Out)"
                    }
                }
            "Microsoft.ActiveDirectory.Management.ADComputer" {
                # Accept objects from AD modules
                $In |%{$Out += $_.DNSHostName}
                Write-Verbose "Target(s) from ADComputer object: $($Out)"
                }
            } # END Switch

        Return $Out

    } # END Fucntion Process-Input

    # Define main function
    function Nbap-Scan {
    
        BEGIN {

            # Check if input is some variation of "Help"
            if ($InputObject -match '/\?|/help|--h|--help') { 
                $MyInvocation = (Get-Variable -Name MyInvocation -Scope Script).Value
                get-help -full ($MyInvocation.MyCommand.Path)   
		        exit 
	        } #END If
        } #END BEGIN
    
        PROCESS {
            
            # Initialise target array
            $Targets = @()

            # Check if input is a generic array or single object and pass to ProcessInput function
            if($InputObject.GetType().FullName -eq "System.Object[]") {
                $InputObject |% {$Targets += Process-Input $_}
                }
            else {
                $Targets = Process-Input $InputObject
            }

            foreach ($Target in $Targets) {

                # Confirm that target is not empty
                if($Target -ne "") {
                    
                    # Initialise Output Object
                    $OutputObject = New-Object psobject -Property @{
                        Target = $Target;
                        Arguments = $Arguments;
                        StartTime = Get-Date;
                        FinishTime = $NULL;
                        Duration = $NULL;
                        OutFile = $NULL;
                        Hash = $NULL
                    }

                    # Remove "/" from output file name in order to not break
                    $OutputFile = "$($OutDir)\$($Target.Replace("/", "-")).xml"
                    $OutputObject.OutFile = $OutputFile

                    # Construct command line for nmap                    
                    $FullCommand = "$($Arguments) -oX $OutputFile $($Target)"

                    # Start nmap scan
                    Write-Verbose "Scan started at $($OutputObject.StartTime)"
                    if ($PSCmdlet.ShouldProcess($Target,"$($Location) $($Arguments)")) {
                        Start-Process $Location -ArgumentList $FullCommand -Wait
                        }
                    $OutputObject.FinishTime = Get-Date
                    Write-Verbose "Scan completed at $($OutputObject.FinishTime)"
                    $OutputObject.Duration = $OutputObject.FinishTime - $OutputObject.StartTime

                    # Once scan completes, check for existence of output file 
                    if(Test-Path $OutputFile) {
                        Write-Verbose "Output file $($OutputFile) saved successfully"
                        $OutputObject.Hash = (Get-FileHash -Algorithm SHA256 $OutputFile).Hash
                        }
                    else {
                        Write-Verbose "Output file $($OutputFile) not found!"
                        }
                    # Send $OutputObject to pipeline
                    $OutputObject
                    }
            } # END ForEach
        } # END PROCESS
    
        END {

            Write-Verbose "Processing completed"
        }

    } # END Function Nbap-Scan

}

PROCESS {Nbap-Scan}

END {

    $ScriptEnd = Get-Date
    $TimeTaken =  $ScriptEnd - $ScriptStart 
    Write-Verbose "Script completed in $($TimeTaken.Minutes) minutes and $($TimeTaken.Seconds) seconds"
} 
