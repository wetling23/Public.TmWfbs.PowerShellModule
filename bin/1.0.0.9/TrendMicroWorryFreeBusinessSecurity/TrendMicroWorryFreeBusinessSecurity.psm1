Function Add-EventLogSource {
    <#
        .DESCRIPTION
            Adds an Event Log source, for script/module logging. Adding an Event Log source requires administrative rights.
        .NOTES 
            Author: Mike Hashemi
            V1.0.0.0 date: 19 April 2017
                - Initial release.
            V1.0.0.1 date: 1 May 2017
                - Minor updates to status handling.
            V1.0.0.2 date: 4 May 2017
                - Added additional return value.
            V1.0.0.3 date: 22 May 2017
                - Changed output to reduce the number of "Write-Host" messages.
            V1.0.0.4 date: 21 June 2017
                - Fixed typo.
                - Significantly improved performance.
                - Changed logging.
            V1.0.0.5 date: 21 June 2017
                - Added a return value if the event log source exists.
            V1.0.0.6 date: 28 June 2017
                - Added [CmdletBinding()].
            V1.0.0.7 date: 28 June 2017
                - Added a check for the source, then a check on the status of the query.
            V1.0.0.8 date: 13 March 2018
                - Updated whitespace.
                - Updated output to only output status on 'verbose'.
            V1.0.0.9 date: 23 August 2019
        .PARAMETER EventLogSource
            Mandatory parameter. This parameter is used to specify the event source, that script/modules will use for logging.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        $EventLogSource
    )

    $message = ("{0}: Beginning {1}." -f [datetime]::Now, $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose']) { Write-Verbose $message }

    # Check if $EventLogSource exists as a source. If the shell is not elevated and the check fails to access the Security log, assume the source does not exist.
    Try {
        $sourceExists = [System.Diagnostics.EventLog]::SourceExists("$EventLogSource")
    }
    Catch {
        $sourceExists = $False
    }

    If ($sourceExists -eq $False) {
        $message = ("{0}: The event source `"{1}`" does not exist. Prompting for elevation." -f [datetime]::Now, $EventLogSource)
        Write-Host $message -ForegroundColor White

        Try {
            Start-Process PowerShell -Verb RunAs -ArgumentList "New-EventLog -LogName Application -Source $EventLogSource -ErrorAction Stop"
        }
        Catch [System.InvalidOperationException] {
            $message = ("{0}: It appears that the user cancelled the operation." -f [datetime]::Now)
            Write-Host $message -ForegroundColor Yellow
            Return "Error"
        }
        Catch {
            $message = ("{0}: Unexpected error launching an elevated Powershell session. The specific error is: {1}" -f [datetime]::Now, $_.Exception.Message)
            Write-Host $message -ForegroundColor Red
            Return "Error"
        }

        Return "Success"
    }
    Else {
        $message = ("{0}: The event source `"{1}`" already exists. There is no action for {2} to take." -f [datetime]::Now, $EventLogSource, $MyInvocation.MyCommand)
        Write-Verbose $message

        Return "Success"
    }
} #1.0.0.9
Function Get-TmWfbsComputer {
    <#
        .DESCRIPTION

        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 3 June 2019
                - Initial release.
            V1.0.0.1 date: 4 June 2019
                - Updated variable name.
                - Added GitHub link.
            V1.0.0.2 date: 16 July 2019
            V1.0.0.3 date: 23 July 2019
            V1.0.0.4 date: 20 December 2019

            https://cspi.trendmicro.com/docs/en-us/service-management-api/v28/reference/wfbss/components/get.aspx
        .LINK
            https://github.com/wetling23/Public.TmWfbs.PowerShellModule
        .PARAMETER AccessToken
            Represents the access token used to connected to TrendMicro's SMPI REST API.
        .PARAMETER SecretKey
            Represents the secret key used to connected to TrendMicro's SMPI REST API.
        .PARAMETER CustomerName
            Represents name of the desired customer.
        .PARAMETER CustomerId
            Represents customer ID of the desired customer.
        .PARAMETER ComputerId
            Represents computer ID of the desired computer.
        .PARAMETER BaseUrl
            Represents the base URL of TrendMicro's SMPI REST API.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputer -AccessToken <access token> -SecretKey <SecretKey> -Verbose

            In this example, the function will search for all customers and will return their properties. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputer -AccessToken <access token> -SecretKey <SecretKey> -Id A5D6DED5-4928-9CEF-B988-EDA3FE11FED3

            In this example, the function will search for the customer with the ID "A5D6DED5-4928-9CEF-B988-EDA3FE11FED3" and will return its properties.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputer -AccessToken <access token> -SecretKey <SecretKey> -Name "Customer 1"

            In this example, the function will search for the customer with the name "Customer 1" and will return its properties.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputer -AccessToken <access token> -SecretKey <SecretKey> -Name "the"

            In this example, the function will search for the customer with "the" in the name and will return their properties.
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [SecureString]$SecretKey,

        [Parameter(Mandatory, ParameterSetName = 'All')]
        [string]$CustomerName,

        [Parameter(Mandatory, ParameterSetName = 'CustomerId')]
        [guid]$CustomerId,

        [string[]]$ComputerId,

        [ValidateSet('aa', 'ip_addr', 'platform', 'arch', 'components', 'version', 'scan_mode', 'ss_service', 'pop3_scan', 'virus_detected', 'spyware_detected', 'spam_detected', 'urlfilter_violated', 'type', 'status', 'phone_number', 'mac_addr', 'last_connect_time', 'sched_start_time', 'sched_complete_time', 'manual_start_time', 'manual_complete_time')]
        [string[]]$Fields,

        $BaseUrl = "https://cspi.trendmicro.com",

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    $message = ("{0}: Operating in the `"{1}`" ParameterSet." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    # Initialize variables
    $epoch = [Math]::Round((New-TimeSpan -start(Get-Date -Date "1/1/1970") -end(Get-Date).ToUniversalTime()).TotalSeconds)
    $httpMethod = "GET"
    $CustomerName = $CustomerName.Replace(" ", "%20")
    $internalSecret_Key = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecretKey))

    If ($PSBoundParameters['Verbose']) {
        $commandParams = @{
            Verbose = $true
        }

        If ($EventLogSource -and (-NOT $LogPath)) {
            $CommandParams.Add('EventLogSource', $EventLogSource)
        }
        ElseIf ($LogPath -and (-NOT $EventLogSource)) {
            $CommandParams.Add('LogPath', $LogPath)
        }
    }
    Else {
        If ($EventLogSource -and (-NOT $LogPath)) {
            $commandParams = @{
                EventLogSource = $EventLogSource
            }
        }
        ElseIf ($LogPath -and (-NOT $EventLogSource)) {
            $commandParams = @{
                LogPath = $LogPath
            }
        }
    }

    If ($ComputerId) {
        $ComputerId = "&ccids=$($ComputerId -join ",")"

        $message = ("{0}: The value of `$ComputerId is {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), ($ComputerId | Out-String))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
    }
    Else {
        $ComputerId = $null
    }

    #region in-line functions
    Function get_content_md5([String] $content) {
        $message = ("{0}: Getting MD5." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        $utf8 = new-object -TypeName System.Text.UTF8Encoding
        $digest = [System.Convert]::ToBase64String($md5.ComputeHash($utf8.GetBytes($content)))
        # Write-Host $digest
        return $digest
    }
    Function calc_signature([String] $internalSecret_Key, [String] $x_posix_time, [String] $request_httpMethod, [String] $request_uri, [String] $content) {
        $message = ("{0}: Calculate signature." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $payload = $x_posix_time + $request_httpMethod.ToUpper() + $request_uri
        if ($content) {
            $payload += get_content_md5($content)
        }
        # Write-Host "payload: $payload"
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes($internalSecret_Key)
        $signature = [System.Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload)))
        # Write-Host "signature: $signature"
        return $signature
    }
    Function generate_cspi_headers($httpMethod, $uri, $AccessToken, $internalSecret_Key, $posix_time, $content) {
        $message = ("{0}: Generate CSPI headers." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $signature = calc_signature $internalSecret_Key $posix_time $httpMethod $uri $content
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Content-Type", "application/json")
        $headers.Add("x-access-token", $AccessToken)
        $headers.Add("x-signature", $signature)
        $headers.Add("x-posix-time", $posix_time)
        $headers.Add("x-traceid", (New-Guid))
        return $headers
    }
    #endregion in-line functions

    $message = ("{0}: Attempting to get customer info, based on whether the customer name or Id were passed." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    If ($CustomerName) {
        $customers = [System.Collections.Generic.List[object]]@((Get-TmWfbsCustomer -AccessToken $AccessToken -SecretKey $SecretKey -Name $CustomerName @commandParams).customers)
    }
    ElseIf ($CustomerId) {
        $customers = [System.Collections.Generic.List[object]]@((Get-TmWfbsCustomer -AccessToken $AccessToken -SecretKey $SecretKey -Id $CustomerId @commandParams).customers)
    }

    If ((($CustomerName) -or ($CustomerId)) -AND (-NOT($customers))) {
        $message = ("{0}: Unable to locate the requested customer. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

        Return
    }

    $customers | ForEach-Object {
        $customer = $_
        $currentLoopCount = 0
        $maxLoopCount = 0
        $list = [System.Collections.Generic.List[object]]::new()
        $page = 1
        $epoch = [Math]::Round((New-TimeSpan -start(Get-Date -Date "1/1/1970") -end(Get-Date).ToUniversalTime()).TotalSeconds) # Resetting, in case of long-run time.

        $message = ("{0}: Looking for computers at: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $customer.name)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        While ($currentLoopCount -le $maxLoopCount) {
            $message = ("{0}: Current loop count is: {1} of {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $currentLoopCount, $maxLoopCount)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $resourcePath = "/SMPI/v2.8/service/wfbss/api/components?cids=$($customer.Id)&page=$page$ComputerId"

            $message = ("{0}: The value of `$resourcePath is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $message = ("{0}: Generating header for Invoke-RestMethod to use." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $headers = generate_cspi_headers $httpMethod $resourcePath $AccessToken $internalSecret_Key $epoch ""

            Try {
                $response = Invoke-RestMethod -Uri "$BaseUrl$resourcePath" -Method $httpMethod -Headers $headers -UseBasicParsing -ErrorAction Stop
            }
            Catch {
                $message = ("{0}: Error running Invoke-RestMethod. To prevent errors, {1} will exit. The specific error is: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

                Return "Error"
            }

            $list.AddRange($response.customers)

            $maxLoopCount = $response.paging.total / $response.paging.limit

            $message = ("{0}: The value of `$maxLoopCount is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $maxLoopCount)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $currentLoopCount++
            $page++
        }

        If ($list.computers.count -gt 0) {
            # Convert last_connect_time from Unix to regular UTC, for each computer
            $list.computers | ForEach-Object {
                $_ | Add-Member -MemberType NoteProperty -Name last_connect_time_human -Value (New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds($_.last_connect_time) -Force
                $_ | Add-Member -MemberType NoteProperty -Name CustomerName -Value $customer.name -Force
            }
        }
        Else {
            $message = ("{0}: No computers found at: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $customer.name)
            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message }
        }

        $message = ("{0}: Returning {1} computers." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $list.computers.count)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $list
    }
} #1.0.0.4
Function Get-TmWfbsCustomer {
    <#
        .DESCRIPTION
            Retrieves a customer instance from Trend Micro's SMPI REST API. If no customer name or ID are provided, the command returns properties of all customers.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 3 June 2019
                - Initial release.
            V1.0.0.1 date: 4 June 2019
                - Added GitHub link.
            V1.0.0.2 date: 9 July 2019
            V1.0.0.3 date: 23 July 2019
            V1.0.0.4 date: 20 December 2019

            https://cspi.trendmicro.com/docs/en-us/service-management-api/v28/reference/wfbss/customers/get.aspx
        .LINK
            https://github.com/wetling23/Public.TmWfbs.PowerShellModule
        .PARAMETER AccessToken
            Represents the access token used to connected to TrendMicro's SMPI REST API.
        .PARAMETER SecretKey
            Represents the secret key used to connected to TrendMicro's SMPI REST API.
        .PARAMETER Name
            Represents name of the desired customer.
        .PARAMETER Id
            Represents customer ID of the desired customer.
        .PARAMETER BaseUrl
            Represents the base URL of TrendMicro's SMPI REST API.
        .PARAMETER EventLogSource
            When included, (and when LogPath is null), represents the event log source for the Application log. If no event log source or path are provided, output is sent only to the host.
        .PARAMETER LogPath
            When included (when EventLogSource is null), represents the file, to which the cmdlet will output will be logged. If no path or event log source are provided, output is sent only to the host.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputers -AccessToken <access token> -SecretKey <SecretKey> -Verbose

            In this example, the function will search for all customers and will return their properties. Verbose output is sent to the host.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputers -AccessToken <access token> -SecretKey <SecretKey> -Id A5D6DED5-4928-9CEF-B988-EDA3FE11FED3

            In this example, the function will search for the customer with the ID "A5D6DED5-4928-9CEF-B988-EDA3FE11FED3" and will return its properties.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputers -AccessToken <access token> -SecretKey <SecretKey> -Name "Customer 1"

            In this example, the function will search for the customer with the name "Customer 1" and will return its properties.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputers -AccessToken <access token> -SecretKey <SecretKey> -Name "the"

            In this example, the function will search for the customer with "the" in the name and will return their properties.
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    Param (
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [SecureString]$SecretKey,

        [Parameter(Mandatory, ParameterSetName = 'CustomerName')]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'CustomerId')]
        [guid]$Id,

        $BaseUrl = "https://cspi.trendmicro.com",

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    $message = ("{0}: Operating in the `"{1}`" ParameterSet." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

    # Initialize variables
    $epoch = [Math]::Round((New-TimeSpan -start(Get-Date -Date "1/1/1970") -end(Get-Date).ToUniversalTime()).TotalSeconds)
    $currentLoopCount = 0
    $maxLoopCount = 0
    $list = [System.Collections.Generic.List[object]]::new()
    $page = 1
    $httpMethod = "GET"
    $Name = $Name.Replace(" ", "%20")
    $internalSecretKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecretKey))

    If ($PSBoundParameters['Verbose']) {
        $commandParams = @{
            Verbose = $true
        }

        If ($EventLogSource -and (-NOT $LogPath)) {
            $CommandParams.Add('EventLogSource', $EventLogSource)
        }
        ElseIf ($LogPath -and (-NOT $EventLogSource)) {
            $CommandParams.Add('LogPath', $LogPath)
        }
    }
    Else {
        If ($EventLogSource -and (-NOT $LogPath)) {
            $commandParams = @{
                EventLogSource = $EventLogSource
            }
        }
        ElseIf ($LogPath -and (-NOT $EventLogSource)) {
            $commandParams = @{
                LogPath = $LogPath
            }
        }
    }

    #region in-line functions
    Function get_content_md5([String] $content) {
        $message = ("{0}: Getting MD5." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        $utf8 = new-object -TypeName System.Text.UTF8Encoding
        $digest = [System.Convert]::ToBase64String($md5.ComputeHash($utf8.GetBytes($content)))
        # Write-Host $digest
        return $digest
    }
    Function calc_signature([String] $internalSecret_Key, [String] $x_posix_time, [String] $request_httpMethod, [String] $request_uri, [String] $content) {
        $message = ("{0}: Calculate signature." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $payload = $x_posix_time + $request_httpMethod.ToUpper() + $request_uri
        if ($content) {
            $payload += get_content_md5($content)
        }
        # Write-Host "payload: $payload"
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes($internalSecret_Key)
        $signature = [System.Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload)))
        # Write-Host "signature: $signature"
        return $signature
    }
    Function generate_cspi_headers($httpMethod, $uri, $AccessToken, $internalSecret_Key, $posix_time, $content) {
        $message = ("{0}: Generate CSPI headers." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

        $signature = calc_signature $internalSecret_Key $posix_time $httpMethod $uri $content
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Content-Type", "application/json")
        $headers.Add("x-access-token", $AccessToken)
        $headers.Add("x-signature", $signature)
        $headers.Add("x-posix-time", $posix_time)
        $headers.Add("x-traceid", (New-Guid))
        return $headers
    }
    #endregion in-line functions

    Switch ($PsCmdlet.ParameterSetName) {
        "CustomerId" {
            $resourcePath = "/SMPI/v2.8/service/wfbss/api/customers?cids=$Id"

            $message = ("{0}: Set `$resourcePath to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        }
        "CustomerName" {
            $resourcePath = "/SMPI/v2.8/service/wfbss/api/customers?q=$Name"

            $message = ("{0}: Set `$resourcePath to: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }
        }
    }

    Switch ($PsCmdlet.ParameterSetName) {
        { $_ -in ("CustomerId", "CustomerName") } {
            $message = ("{0}: Generating header for Invoke-RestMethod to use." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $headers = generate_cspi_headers $httpMethod $resourcePath $AccessToken $internalSecretKey $epoch ""

            $message = ("{0}: Attempting to retrieve instance." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            Try {
                $response = Invoke-RestMethod -Uri "$BaseUrl$resourcePath" -Method $httpMethod -Headers $headers -UseBasicParsing -ErrorAction Stop
            }
            Catch {
                $message = ("{0}: Error running Invoke-RestMethod. To prevent errors, {1} will exit. The specific error is: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

                Return "Error"
            }

            $message = ("{0}: Returning {1} customers." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $list.count)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $response
        }
        "All" {
            While ($currentLoopCount -le $maxLoopCount) {
                $message = ("{0}: Current loop count is: {1} of {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $currentLoopCount, $maxLoopCount)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $resourcePath = "/SMPI/v2.8/service/wfbss/api/customers?page=$page"

                $message = ("{0}: The value of `$resourcePath is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $message = ("{0}: Generating header for Invoke-RestMethod to use." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $headers = generate_cspi_headers $httpMethod $resourcePath $AccessToken $internalSecretKey $epoch ""

                $message = ("{0}: Attempting to retrieve page {1} of instances." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $page)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                Try {
                    $response = Invoke-RestMethod -Uri "$BaseUrl$resourcePath" -Method $httpMethod -Headers $headers -ErrorAction Stop
                }
                Catch {
                    $message = ("{0}: Error running Invoke-RestMethod. To prevent errors, {1} will exit. The specific error is: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

                    Return "Error"
                }

                $list.AddRange($response.customers)

                $maxLoopCount = $response.paging.total / $response.paging.limit

                $message = ("{0}: The value of `$maxLoopCount is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $maxLoopCount)
                If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

                $currentLoopCount++
                $page++
            }

            $message = ("{0}: Returning {1} customers." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $list.count)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message } }

            $list
        }
    }
} #1.0.0.4
Function Out-PsLogging {
    <#
        .DESCRIPTION
            Logging function, for host, event log, or a log file.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 3 December 2019
                - Initial release.
            V1.0.0.1 date: 7 January 2020
            V1.0.0.2 date: 22 January 2020
            V1.0.0.3 date: 17 March 2020
            V1.0.0.4 date: 15 June 2020
            V1.0.0.5 date: 30 June 2020
        .LINK
            https://github.com/wetling23/logicmonitor-posh-module
        .PARAMETER EventLogSource
            Default parameter set. Represents the Windows Application log event source.
        .PARAMETER LogPath
            Path and file name of the target log file. If the file does not exist, the cmdlet will create it.
        .PARAMETER ScreenOnly
            When this switch parameter is included, the logging output is written only to the host.
        .PARAMETER Message
            Message to output.
        .PARAMETER MessageType
            Type of message to output. Valid values are "Info", "Warning", "Error", and "Verbose". When writing to a log file, all output is "info" but will be written to the host, with the appropriate message type.
        .PARAMETER BlockStdErr
            When set to $True, the cmdlet will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
        .EXAMPLE
            PS C:\> Out-PsLogging -Message "Test" -MessageType Info -LogPath C:\Temp\log.txt

            In this example, the message, "Test" will be written to the host and appended to C:\Temp\log.txt. If the path does not exist, or the user does not have write access, the message will only be written to the host.
        .EXAMPLE
            PS C:\> Out-PsLogging -Message "Test" -MessageType Warning -EventLogSource TestScript

            In this example, the message, "Test" will be written to the host and to the Windows Application log, as a warning and with the event log source/event ID "TestScript"/5417.
            If the event source does not exist and the session is elevated, the event source will be created.
            If the event source does not exist and the session is not elevated, the message will only be written to the host.
        .EXAMPLE
            PS C:\> Out-PsLogging -Message "Test" -MessageType Verbose -ScreenOnly

            In this example, the message, "Test" will be written to the host as a verbose message.
    #>
    [CmdletBinding(DefaultParameterSetName = 'SessionOnly')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'EventLog')]
        [string]$EventLogSource,

        [ValidateScript( {
                If (-NOT ($_ | Split-Path -Parent | Test-Path) ) {
                    Throw "Path does not exist."
                }
                If (-NOT ($_ | Test-Path) ) {
                    "" | Add-Content -Path $_
                }
                If (-NOT ($_ | Test-Path -PathType Leaf) ) {
                    Throw "The LogPath argument must be a file."
                }
                Return $true
            })]
        [Parameter(Mandatory, ParameterSetName = 'File')]
        [System.IO.FileInfo]$LogPath,

        [switch]$ScreenOnly,

        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Warning', 'Error', 'Verbose', 'First')]
        [string]$MessageType,

        [boolean]$BlockStdErr
    )

    # Initialize variables.
    $elevatedSession = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    If ($PsCmdlet.ParameterSetName -eq "EventLog") {
        If ([System.Diagnostics.EventLog]::SourceExists("$EventLogSource")) {
            # The event source does not exists, nothing else to do.

            $logType = "EventLog"
        }
        ElseIf (-NOT ([System.Diagnostics.EventLog]::SourceExists("$EventLogSource")) -and $elevatedSession) {
            # The event source does not exist, but the session is elevated, so create it.
            Try {
                New-EventLog -LogName Application -Source $EventLogSource -ErrorAction Stop

                $logType = "EventLog"
            }
            Catch {
                Write-Error ("{0}: Unable to create the event source ({1}). No logging will be done." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $EventLogSource)

                $logType = "SessionOnly"
            }
        }
        ElseIf (-NOT $elevatedSession) {
            # The event source does not exist, and the session is not elevated.
            Write-Error ("{0}: The event source ({1}) does not exist and the command was not run in an elevated session, unable to create the event source. No logging will be done." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $EventLogSource)

            $logType = "SessionOnly"
        }
    }
    ElseIf ($PsCmdlet.ParameterSetName -eq "File") {
        # Check if we have rights to the path in $LogPath.
        Try {
            [System.Io.File]::OpenWrite($LogPath).Close()
        }
        Catch {
            Write-Error ("{0}: Unable to write to the log file path ({1}). No logging will be done." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $LogPath)

            $logType = "SessionOnly"
        }

        $logType = "LogFile"
    }
    Else {
        $logType = "SessionOnly"
    }

    Switch ($logType) {
        "SessionOnly" {
            Switch ($MessageType) {
                "Info" { Write-Host $Message }
                "Warning" { Write-Warning $Message }
                "Error" { If ($BlockStdErr) { Write-Host $Message -ForegroundColor Red } Else { Write-Error $Message } }
                "Verbose" { Write-Verbose $Message -Verbose }
                "First" { Write-Verbose $Message -Verbose }
            }
        }
        "EventLog" {
            Switch ($MessageType) {
                "Info" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $Message -EventId 5417; Write-Host $Message }
                "Warning" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Warning -Message $Message -EventId 5417; Write-Warning $Message }
                "Error" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $Message -EventId 5417; If ($BlockStdErr) { Write-Host $Message -ForegroundColor Red } Else { Write-Error $Message } }
                "Verbose" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $Message -EventId 5417; Write-Verbose $Message -Verbose }
                "First" { Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $Message -EventId 5417; Write-Verbose $Message -Verbose }
            }
            If ($BlockStdErr) {

            }
        }
        "LogFile" {
            Switch ($MessageType) {
                "Info" { [System.IO.File]::AppendAllLines([string]$LogPath, [string[]]$Message); Write-Host $Message }
                "Warning" { [System.IO.File]::AppendAllLines([string]$LogPath, [string[]]$Message); Write-Warning $Message }
                "Error" { [System.IO.File]::AppendAllLines([string]$LogPath, [string[]]$Message); If ($BlockStdErr) { Write-Host $Message -ForegroundColor Red } Else { Write-Error $Message } }
                "Verbose" { [System.IO.File]::AppendAllLines([string]$LogPath, [string[]]$Message); Write-Verbose $Message -Verbose }
                "First" { [System.IO.File]::WriteAllLines($LogPath, $Message); Write-Verbose $Message -Verbose }
            }
        }
    }
} #1.0.0.5
Export-ModuleMember -Alias * -Function *
