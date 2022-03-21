Function Get-TmWfbsComputer {
    <#
        .DESCRIPTION
            Retrieve customers, then retrieve computers for that customer. Alternatively, provide a computer ID to retrieve that device specifically. Finally, omit customer name/ID and computer ID to retrieve all computers.
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
            V1.0.0.5 date: 30 June 2020
            V1.0.0.6 date: 5 October 2021
            V2022.02.18.0
            V2022.03.01.0
            V2022.03.02.0
            V2022.03.21.0

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
        .PARAMETER BlockStdErr
            When set to $True, the script will block "Write-Error". Use this parameter when calling from wscript. This is required due to a bug in wscript (https://groups.google.com/forum/#!topic/microsoft.public.scripting.wsh/kIvQsqxSkSk).
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

        [Parameter(Mandatory, ParameterSetName = 'CustomerName')]
        [string]$CustomerName,

        [Parameter(Mandatory, ParameterSetName = 'CustomerId')]
        [guid]$CustomerId,

        [string[]]$ComputerId,

        [ValidateSet('aa', 'ip_addr', 'platform', 'arch', 'components', 'version', 'scan_mode', 'ss_service', 'pop3_scan', 'virus_detected', 'spyware_detected', 'spam_detected', 'urlfilter_violated', 'type', 'status', 'phone_number', 'mac_addr', 'last_connect_time', 'sched_start_time', 'sched_complete_time', 'manual_start_time', 'manual_complete_time')]
        [string[]]$Fields,

        $BaseUrl = "https://cspi.trendmicro.com",

        [boolean]$BlockStdErr = $false,

        [string]$EventLogSource,

        [string]$LogPath
    )

    $message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

    #region setup
    $message = ("{0}: Operating in the `"{1}`" ParameterSet." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $PsCmdlet.ParameterSetName)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

    # Initialize variables
    $epoch = [Math]::Round((New-TimeSpan -start(Get-Date -Date "1/1/1970") -end(Get-Date).ToUniversalTime()).TotalSeconds)
    $httpMethod = "GET"
    $internalSecret_Key = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecretKey))
    $list = [System.Collections.Generic.List[object]]::new()

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
        Else {
            $commandParams = @{
                Verbose = $false
            }
        }
    }

    #region in-line functions
    Function get_content_md5([String] $content) {
        $message = ("{0}: Getting MD5." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

        $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        $utf8 = new-object -TypeName System.Text.UTF8Encoding
        $digest = [System.Convert]::ToBase64String($md5.ComputeHash($utf8.GetBytes($content)))
        # Write-Host $digest
        return $digest
    }
    Function calc_signature([String] $internalSecret_Key, [String] $x_posix_time, [String] $request_httpMethod, [String] $request_uri, [String] $content) {
        $message = ("{0}: Calculate signature." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

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
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

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
    #endregion setup

    $message = ("{0}: Attempting to get customer data, before getting computer data." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

    Switch ($PsCmdlet.ParameterSetName) {
        "CustomerName" {
            $message = ("{0}: Getting customer: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $CustomerName)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

            $CustomerName = $CustomerName.Replace(" ", "%20")

            $customers = [System.Collections.Generic.List[object]]@((Get-TmWfbsCustomer -AccessToken $AccessToken -SecretKey $SecretKey -Name $CustomerName @commandParams))
        }
        "CustomerId" {
            $message = ("{0}: Getting customer: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $CustomerId)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

            $customers = [System.Collections.Generic.List[object]]@((Get-TmWfbsCustomer -AccessToken $AccessToken -SecretKey $SecretKey -Id $CustomerId @commandParams))
        }
        "All" {
            $message = ("{0}: Getting all customers." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

            $customers = [System.Collections.Generic.List[object]]@((Get-TmWfbsCustomer -AccessToken $AccessToken -SecretKey $SecretKey @commandParams))
        }
    }

    If ($ComputerId) {
        $ComputerId = "&ccids=$($ComputerId -join ",")"
    } Else {
        $ComputerId = $null
    }

    If ($customers.customers.eid) {
        $message = ("{0}: Pulling customer properties out of `$customers.customers." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

        $customers = $customers.customers
    } ElseIf (($customers -eq "Error") -or ($null -eq $customers)) {
        $message = ("{0}: No customers were retrieved, unable to continue." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

        Return "Error"
    }

    Foreach ($customer in $customers) {
        $currentLoopCount = 0
        $maxLoopCount = 5
        $customerList = [System.Collections.Generic.List[object]]::new()
        $page = 1
        $epoch = [Math]::Round((New-TimeSpan -start(Get-Date -Date "1/1/1970") -end(Get-Date).ToUniversalTime()).TotalSeconds) # Resetting, in case of long-run time.
        $response = $null

        $message = ("{0}: Looking for computers at: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $customer.name)
        If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

        While ($currentLoopCount -le $maxLoopCount) {
            $message = ("{0}: Current loop count is: {1} of {2}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $currentLoopCount, $maxLoopCount)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

            $resourcePath = "/SMPI/v2.8/service/wfbss/api/components?cids=$($customer.Id)&page=$page$ComputerId"

            $message = ("{0}: The value of `$resourcePath is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $resourcePath)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

            $message = ("{0}: Generating header for Invoke-RestMethod to use." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

            $headers = generate_cspi_headers $httpMethod $resourcePath $AccessToken $internalSecret_Key $epoch ""

            Try {
                $response = Invoke-RestMethod -Uri "$BaseUrl$resourcePath" -Method $httpMethod -Headers $headers -UseBasicParsing -ErrorAction Stop

                $currentLoopCount++
                $page++
            }
            Catch {
                If (([datetime]$customer.expire -lt (Get-Date)) -and ($_.Exception.Message -match '.*404 \(Not Found\)')) {
                    $message = ("{0}: The customer has expired, no devices returned." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

                    $currentLoopCount++
                    Continue
                }
                Else {
                    $message = ("{0}: Error running Invoke-RestMethod. To prevent errors, {1} will exit. The specific error is: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $_.Exception.Message)
                    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message -BlockStdErr $BlockStdErr }

                    Return "Error"
                }
            }

            If ($ComputerId) {
                $customerList.Add($response.customers.computers)
            } Else {
                $customerList.AddRange($response.customers.computers)
            }

            $maxLoopCount = $response.paging.total / $response.paging.limit

            $message = ("{0}: The value of `$maxLoopCount is: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $maxLoopCount)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }
        }

        If ($customerList.id.count -gt 0) {
            # Convert last_connect_time from Unix to regular UTC, for each computer.
            Foreach ($item in $customerList) {
                $item | Add-Member -MemberType NoteProperty -Name last_connect_time_human -Value (New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0).AddSeconds($item.last_connect_time) -Force
                $item | Add-Member -MemberType NoteProperty -Name CustomerName -Value $customer.name -Force
                $item | Add-Member -MemberType NoteProperty -Name CustomerId -Value $customer.id -Force
            }
        }
        Else {
            $message = ("{0}: No computers found at: {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $customer.name)
            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Warning -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Warning -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Warning -Message $message -BlockStdErr $BlockStdErr }
        }

        If ($customers.id.Count -gt 1) {
            $message = ("{0}: ---------------------------------------------------------------------------" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $customer.name)
            If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }
        }

        $list.Add($customerList)
    }

    $message = ("{0}: Returning {1} computers." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $list.id.count)
    If ($PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue') { If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } Else { Out-PsLogging -ScreenOnly -MessageType Verbose -Message $message -BlockStdErr $BlockStdErr } }

    $list
} #V2022.03.02.0