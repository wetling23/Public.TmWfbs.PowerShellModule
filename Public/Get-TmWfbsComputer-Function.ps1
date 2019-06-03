Function Get-TmwfbsComputer {
    <#
        .DESCRIPTION

        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 3 June 2019
                - Initial release.

            https://cspi.trendmicro.com/docs/en-us/service-management-api/v28/reference/wfbss/components/get.aspx
        .LINK
            
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
        $message = ("{0}: No computers found at: {1}." -f [datetime]::Now, $customer.name)
        If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Warning $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Warning $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Warning -Message $message -EventId 5417 }
    }

    $list
} #1.0.0.0