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
        .PARAMETER EventLogSource
            Mandatory parameter. This parameter is used to specify the event source, that script/modules will use for logging.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        $EventLogSource
    )

    $message = ("{0}: Beginning {1}." -f (Get-Date -Format s), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose']) {Write-Verbose $message}

    # Check if $EventLogSource exists as a source. If the shell is not elevated and the check fails to access the Security log, assume the source does not exist.
    Try {
        $sourceExists = [System.Diagnostics.EventLog]::SourceExists("$EventLogSource")
    }
    Catch {
        $sourceExists = $False
    }

    If ($sourceExists -eq $False) {
        $message = ("{0}: The event source `"{1}`" does not exist. Prompting for elevation." -f (Get-Date -Format s), $EventLogSource)
        Write-Host $message -ForegroundColor White

        Try {
            Start-Process PowerShell -Verb RunAs -ArgumentList "New-EventLog -LogName Application -Source $EventLogSource -ErrorAction Stop"
        }
        Catch [System.InvalidOperationException] {
            $message = ("{0}: It appears that the user cancelled the operation." -f (Get-Date -Format s))
            Write-Host $message -ForegroundColor Yellow
            Return "Error"
        }
        Catch {
            $message = ("{0}: Unexpected error launching an elevated Powershell session. The specific error is: {1}" -f (Get-Date -Format s), $_.Exception.Message)
            Write-Host $message -ForegroundColor Red
            Return "Error"
        }

        Return "Success"
    }
    Else {
        $message = ("{0}: The event source `"{1}`" already exists. There is no action for {2} to take." -f (Get-Date -Format s), $EventLogSource, $MyInvocation.MyCommand)
        Write-Verbose $message

        Return "Success"
    }
} #1.0.0.8
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

            https://cspi.trendmicro.com/docs/en-us/service-management-api/v28/reference/wfbss/components/get.aspx
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
            Default value is "TmWfbsPowerShellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputers -AccessToken <access token> -SecretKey <SecretKey>

            In this example, the function will search for all customers and will return their properties.
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
        $AccessToken,

        [Parameter(Mandatory)]
        $SecretKey,

        [Parameter(Mandatory, ParameterSetName = 'All')]
        [string]$CustomerName,

        [Parameter(Mandatory, ParameterSetName = 'CustomerId')]
        [guid]$CustomerId,

        [string[]]$ComputerId,

        [ValidateSet('aa', 'ip_addr', 'platform', 'arch', 'components', 'version', 'scan_mode', 'ss_service', 'pop3_scan', 'virus_detected', 'spyware_detected', 'spam_detected', 'urlfilter_violated', 'type', 'status', 'phone_number', 'mac_addr', 'last_connect_time', 'sched_start_time', 'sched_complete_time', 'manual_start_time', 'manual_complete_time')]
        [string[]]$Fields,

        $BaseUrl = "https://cspi.trendmicro.com",

        [string]$EventLogSource = 'TmWfbsPowerShellModule',

        [switch]$BlockLogging
    )

    If (-NOT($BlockLogging)) {
        $return = Add-EventLogSource -EventLogSource $EventLogSource

        If ($return -ne "Success") {
            $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f [datetime]::Now, $EventLogSource)
            Write-Host $message -ForegroundColor Yellow;

            $BlockLogging = $True
        }
    }

    $message = ("{0}: Beginning {1}." -f [datetime]::Now, $MyInvocation.MyCommand)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

    $message = ("{0}: Operating in the `"{1}`" ParameterSet." -f [datetime]::Now, $PsCmdlet.ParameterSetName)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

    # Initialize variables
    $epoch = [Math]::Round((New-TimeSpan -start(Get-Date -Date "1/1/1970") -end(Get-Date).ToUniversalTime()).TotalSeconds)
    $httpMethod = "GET"
    $CustomerName = $CustomerName.Replace(" ", "%20")

    If ($PSBoundParameters['Verbose']) {
        $commandParams = @{
            Verbose        = $true
            EventLogSource = $EventLogSource
        }
    }
    Else {
        $commandParams = @{ EventLogSource = $EventLogSource }
    }

    If ($ComputerId) {
        $ComputerId = "&ccids=$($ComputerId -join ",")"

        $message = ("{0}: The value of `$ComputerId is {1}." -f [datetime]::Now, ($ComputerId | Out-String))
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }
    }
    Else {
        $ComputerId = $null
    }

    #region in-line functions
    Function get_content_md5([String] $content) {
        $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        $utf8 = new-object -TypeName System.Text.UTF8Encoding
        $digest = [System.Convert]::ToBase64String($md5.ComputeHash($utf8.GetBytes($content)))
        # Write-Host $digest
        return $digest
    }
    Function calc_signature([String] $secret_key, [String] $x_posix_time, [String] $request_httpMethod, [String] $request_uri, [String] $content) {
        $payload = $x_posix_time + $request_httpMethod.ToUpper() + $request_uri
        if ($content) {
            $payload += get_content_md5($content)
        }
        # Write-Host "payload: $payload"
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes($secret_key)
        $signature = [System.Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload)))
        # Write-Host "signature: $signature"
        return $signature
    }
    Function generate_cspi_headers($httpMethod, $uri, $access_token, $secret_key, $posix_time, $content) {
        $signature = calc_signature $secret_key $posix_time $httpMethod $uri $content
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Content-Type", "application/json")
        $headers.Add("x-access-token", $access_token)
        $headers.Add("x-signature", $signature)
        $headers.Add("x-posix-time", $posix_time)
        $headers.Add("x-traceid", (New-Guid))
        return $headers
    }
    #endregion in-line functions

    $message = ("{0}: Attempting to get customer info, based on whether the customer name or Id were passed." -f [datetime]::Now, $MyInvocation.MyCommand)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

    If ($CustomerName) {
        $customers = [System.Collections.Generic.List[object]]@((Get-TmWfbsCustomer -AccessToken $AccessToken -SecretKey $SecretKey -Name $CustomerName @commandParams).customers)
    }
    ElseIf ($CustomerId) {
        $customers = [System.Collections.Generic.List[object]]@((Get-TmWfbsCustomer -AccessToken $AccessToken -SecretKey $SecretKey -Id $CustomerId @commandParams).customers)
    }

    If (-NOT($customers)) {
        $message = ("{0}: Unable to locate the requested customer. To prevent errors, {1} will exit." -f [datetime]::Now, $MyInvocation.MyCommand)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Error $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Error $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Error -Message $message -EventId 5417 }

        Return
    }

    $currentLoopCount = 0
    $maxLoopCount = 0
    $list = [System.Collections.Generic.List[object]]::new()
    $page = 1
    While ($currentLoopCount -le $maxLoopCount) {
        $message = ("{0}: Current loop count is: {0}." -f [datetime]::Now, $currentLoopCount)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

        $resourcePath = "/SMPI/v2.8/service/wfbss/api/components?cids=$($customers.Id)&page=$page$ComputerId"

        $message = ("{0}: Attempting to generate headers." -f [datetime]::Now, $resourcePath)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

        $headers = generate_cspi_headers $httpMethod $resourcePath $access_token $secret_key $epoch ""

        $response = Invoke-RestMethod -Uri "$BaseUrl$resourcePath" -Method $httpMethod -Headers $headers

        $list.AddRange($response.customers)

        $maxLoopCount = $response.paging.total / $response.paging.limit

        $message = ("{0}: The value of `$maxLoopCount is: {1}." -f [datetime]::Now, $maxLoopCount)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

        $currentLoopCount++
        $page++
    }

    If ($list.computers.count -gt 0) {
        # Convert last_connect_time from Unix to regular UTC, for each computer
        $list.computers | ForEach-Object {
            $_ | Add-Member -MemberType NoteProperty -Name last_connect_time_human -Value (New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds($_.last_connect_time) -Force
            $_ | Add-Member -MemberType NoteProperty -Name CustomerName -Value $customers.name -Force
        }
    }
    Else {
        $message = ("{0}: No computers found at: {1}." -f [datetime]::Now, $customers.name)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Warning $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Warning $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Warning -Message $message -EventId 5417 }
    }

    $list
} #1.0.0.1
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
            Default value is "TmWfbsPowerShellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputers -AccessToken <access token> -SecretKey <SecretKey>

            In this example, the function will search for all customers and will return their properties.
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
        $AccessToken,

        [Parameter(Mandatory)]
        $SecretKey,

        [Parameter(Mandatory, ParameterSetName = 'CustomerName')]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'CustomerId')]
        [guid]$Id,

        $BaseUrl = "https://cspi.trendmicro.com",

        [string]$EventLogSource = 'TmWfbsPowerShellModule',

        [switch]$BlockLogging
    )

    If (-NOT($BlockLogging)) {
        $return = Add-EventLogSource -EventLogSource $EventLogSource

        If ($return -ne "Success") {
            $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f [datetime]::Now, $EventLogSource)
            Write-Host $message -ForegroundColor Yellow;

            $BlockLogging = $True
        }
    }

    $message = ("{0}: Beginning {1}." -f [datetime]::Now, $MyInvocation.MyCommand)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

    $message = ("{0}: Operating in the `"{1}`" ParameterSet." -f [datetime]::Now, $PsCmdlet.ParameterSetName)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

    # Initialize variables
    $epoch = [Math]::Round((New-TimeSpan -start(Get-Date -Date "1/1/1970") -end(Get-Date).ToUniversalTime()).TotalSeconds)
    $currentLoopCount = 0
    $maxLoopCount = 0
    $list = [System.Collections.Generic.List[object]]::new()
    $page = 1
    $httpMethod = "GET"
    $Name = $Name.Replace(" ", "%20")

    Function get_content_md5([String] $content) {
        $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        $utf8 = new-object -TypeName System.Text.UTF8Encoding
        $digest = [System.Convert]::ToBase64String($md5.ComputeHash($utf8.GetBytes($content)))
        # Write-Host $digest
        return $digest
    }
    Function calc_signature([String] $secret_key, [String] $x_posix_time, [String] $request_httpMethod, [String] $request_uri, [String] $content) {
        $payload = $x_posix_time + $request_httpMethod.ToUpper() + $request_uri
        if ($content) {
            $payload += get_content_md5($content)
        }
        # Write-Host "payload: $payload"
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes($secret_key)
        $signature = [System.Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload)))
        # Write-Host "signature: $signature"
        return $signature
    }
    Function generate_cspi_headers($httpMethod, $uri, $access_token, $secret_key, $posix_time, $content) {
        $signature = calc_signature $secret_key $posix_time $httpMethod $uri $content
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Content-Type", "application/json")
        $headers.Add("x-access-token", $access_token)
        $headers.Add("x-signature", $signature)
        $headers.Add("x-posix-time", $posix_time)
        $headers.Add("x-traceid", (New-Guid))
        return $headers
    }

    Switch ($PsCmdlet.ParameterSetName) {
        "CustomerId" {
            $resourcePath = "/SMPI/v2.8/service/wfbss/api/customers?cids=$Id"

            $message = ("{0}: Set `$resourcePath to: {1}." -f [datetime]::Now, $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }
        }
        "CustomerName" {
            $resourcePath = "/SMPI/v2.8/service/wfbss/api/customers?q=$Name"

            $message = ("{0}: Set `$resourcePath to: {1}." -f [datetime]::Now, $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }
        }
    }

    Switch ($PsCmdlet.ParameterSetName) {
        { $_ -in ("CustomerId", "CustomerName") } {
            $message = ("{0}: Attempting to generate headers." -f [datetime]::Now, $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

            $headers = generate_cspi_headers $httpMethod $resourcePath $access_token $secret_key $epoch ""

            $message = ("{0}: Attempting to retrieve instance." -f [datetime]::Now, $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

            $response = Invoke-RestMethod -Uri "$BaseUrl$resourcePath" -Method $httpMethod -Headers $headers

            $response
        }
        "All" {
            While ($currentLoopCount -le $maxLoopCount) {
                $message = ("{0}: Current loop count is: {0}." -f [datetime]::Now, $currentLoopCount)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $resourcePath = "/SMPI/v2.8/service/wfbss/api/customers?page=$page"

                $message = ("{0}: The value of `$resourcePath is: {0}." -f [datetime]::Now, $resourcePath)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $message = ("{0}: Attempting to generate headers." -f [datetime]::Now, $resourcePath)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $headers = generate_cspi_headers $httpMethod $resourcePath $access_token $secret_key $epoch ""

                $message = ("{0}: Attempting to retrieve page {1} of instances." -f [datetime]::Now, $page)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $response = Invoke-RestMethod -Uri "$BaseUrl$resourcePath" -Method $httpMethod -Headers $headers

                $list.AddRange($response.customers)

                $maxLoopCount = $response.paging.total / $response.paging.limit

                $message = ("{0}: The value of `$maxLoopCount is: {1}." -f [datetime]::Now, $maxLoopCount)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $currentLoopCount++
                $page++
            }

            $list
        }
    }
} #1.0.0.1
Export-ModuleMember -Alias * -Function *
