<#
.SYNOPSIS
   Create and populate WMI Class instances with Registry Key values for ConfigMgr inventory.
.DESCRIPTION
   This script is designed to be re-usable and used in a ConfigMgr CI. Simply update $InvArgs with the information needed to collect data from one or more Registry keys.
.PARAMETER NameSpace
   Required
    WMI Namespace where new class will be created
.PARAMETER NewClassName
   Required
   New WMI class name. Be sure to use a unique class since an existing class will be overwitten.
.PARAMETER CombineKeys
   Set this to True to merge all registry keys into a single WMI instance. Set to False to create new instances for each registry key.
   If set to True, registry keys can contain different properties (though only unique values will be used, so duplicates will be removed).
   If set to False, registry keys must contain the same properties for the best results, but it not required. It's just bad practice.
.PARAMETER RegistryKeyList
    A list of registry key paths that will be collected to be stored into a new instance of the class.
.PARAMETER PropertyConfig
    Use the values here to configure how the keys are imported. Each value accepts an array of values. See .EXAMPLE for details
      KeyProps - The Name of any property that will be used as the key/index for the class. Use "KeyName" indicate that the registry key name will be used as the Key/index for the class.
      ExcludeProps - Name of properties to exclude from inventory

      The Name of any property whose value should be stored as the corresponding WMI Data Type
      Uint32Props
      Uint64Props
      UInt8Props
      UInt16Props
      SInt8Props
      SInt16Props
      SInt32Props
      SInt64Props
      Real32Props
      Real64Props
      BooleanProps
      DateTimeProps
      Char16Props

.NOTES
  Version:        1.3
  Author:         Adam Gross - @AdamGrossTX
  GitHub:           https://www.github.com/AdamGrossTX
  WebSite:          https://www.asquaredozen.com
  Creation Date:  08/09/2019
  Purpose/Change:
   1.0 Initial Release
   1.1 Removed DateCollected. Updated to work on PowerShell 7 and remove WMI calls
   1.2 Updated to be more modular/re-usable.
   1.3 Reworked using base template model


.EXAMPLE
Populate the values in $InvArgs. This gets sent to Get-CustInventory as a splat. Change the name of the arguments in the Main region at the end.

$InvArgs = @{
   NameSpace = "root\cimv2"
   NewClassName = "CM_OSVersionHistory"
   RegistryKeyList = "HKLM:System\Setup\Source OS*","HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion"
   CombineKeys = $false
   UseKeyNameAsKey = $True
   PropertyConfig = @{
      KeyProps = $null
      ExcludeProps = "DigitalProductId", "DigitalProductId4"
      Uint32Props = "BaseBuildRevisionNumber","CurrentMajorVersionNumber","InstallDate","MigrationScope","UBR"
      Uint64Props = "InstallTime"
      UInt8Props = $null
      UInt16Props = $null
      SInt8Props = $null
      SInt16Props = $null
      SInt32Props = $null
      SInt64Props = $null
      Real32Props = $null
      Real64Props = $null
      BooleanProps = $null
      DateTimeProps = $null
      Char16Props = $null
   }
#>

#region Args
 #CM_SetupDiagArgs
 $InvArgs = @{
    NameSpace = "root\cimv2"
    NewClassName = "CM_SetupDiag2"
    RegistryKeyList = "HKLM:System\Setup\MoSetup\Tracking","HKLM:System\Setup\MoSetup\Volatile\SetupDiag"
    CombineKeys = $True
    UseKeyNameAsKey = $False
    PropertyConfig = @{
       KeyProps = "DateTime"
       ExcludeProps = "DigitalProductId", "DigitalProductId4"
       Uint32Props = "InstallAttempts","FailureCount", "RollbackCount"
       Uint64Props = "InstallTime"
       UInt8Props = $null
       UInt16Props = $null
       SInt8Props = $null
       SInt16Props = $null
       SInt32Props = $null
       SInt64Props = $null
       Real32Props = $null
       Real64Props = $null
       BooleanProps = $null
       DateTimeProps = $null
       Char16Props = $null
    }
 }
 #endregion

#region Functions

Function Get-AzureADDeviceInfo {
   Try {
      Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
public class NetAPI32{
    public enum DSREG_JOIN_TYPE {
      DSREG_UNKNOWN_JOIN,
      DSREG_DEVICE_JOIN,
      DSREG_WORKPLACE_JOIN
    }
	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DSREG_USER_INFO {
        [MarshalAs(UnmanagedType.LPWStr)] public string UserEmail;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserKeyId;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserKeyName;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CERT_CONTEX {
        public uint   dwCertEncodingType;
        public byte   pbCertEncoded;
        public uint   cbCertEncoded;
        public IntPtr pCertInfo;
        public IntPtr hCertStore;
    }
	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DSREG_JOIN_INFO
    {
        public int joinType;
        public IntPtr pJoinCertificate;
        [MarshalAs(UnmanagedType.LPWStr)] public string DeviceId;
        [MarshalAs(UnmanagedType.LPWStr)] public string IdpDomain;
        [MarshalAs(UnmanagedType.LPWStr)] public string TenantId;
        [MarshalAs(UnmanagedType.LPWStr)] public string JoinUserEmail;
        [MarshalAs(UnmanagedType.LPWStr)] public string TenantDisplayName;
        [MarshalAs(UnmanagedType.LPWStr)] public string MdmEnrollmentUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string MdmTermsOfUseUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string MdmComplianceUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserSettingSyncUrl;
        public IntPtr pUserInfo;
    }
    [DllImport("netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern void NetFreeAadJoinInformation(
            IntPtr pJoinInfo);
    [DllImport("netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int NetGetAadJoinInformation(
            string pcszTenantId,
            out IntPtr ppJoinInfo);
}
'@

      $pcszTenantId = $null
      $ptrJoinInfo = [IntPtr]::Zero

      # https://docs.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation
      #[NetAPI32]::NetFreeAadJoinInformation([IntPtr]::Zero);
      $retValue = [NetAPI32]::NetGetAadJoinInformation($pcszTenantId, [ref]$ptrJoinInfo);

      # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
      if ($retValue -eq 0) {
         # https://support.microsoft.com/en-us/help/2909958/exceptions-in-windows-powershell-other-dynamic-languages-and-dynamical

         $ptrJoinInfoObject = New-Object NetAPI32+DSREG_JOIN_INFO
         $joinInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrJoinInfo, [System.Type] $ptrJoinInfoObject.GetType())




         Write-Host "Device is $([NetAPI32+DSREG_JOIN_TYPE]($joinInfo.joinType))"
         switch ($joinInfo.joinType) {
            ([NetAPI32+DSREG_JOIN_TYPE]::DSREG_DEVICE_JOIN.value__) { Write-Verbose "Device is joined" }
            ([NetAPI32+DSREG_JOIN_TYPE]::DSREG_UNKNOWN_JOIN.value__) {
               $AADJoin = "ERROR"
               $AADDeviceID = "ERROR"
               $TenantId = "error"
               Throw "error discovered"

            }
            ([NetAPI32+DSREG_JOIN_TYPE]::DSREG_WORKPLACE_JOIN.value__) { Write-Verbose "Device workplace joined" }
         }

         $ptrJoinCertificate = $joinInfo.pJoinCertificate
         $ptrJoinCertificateObject = New-Object NetAPI32+CERT_CONTEX
         $joinCertificate = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrJoinCertificate, [System.Type] $ptrJoinCertificateObject.GetType())
         #$JoinCertificate | fl

         Try {
            #Release pointers
            [System.Runtime.InterOpServices.Marshal]::Release($ptrJoinInfo) | Out-Null
            [System.Runtime.InterOpServices.Marshal]::Release($ptrUserInfo) | Out-Null
            [System.Runtime.InterOpServices.Marshal]::Release($ptrJoinCertificate) | Out-Null
         }
         Catch {

         }
      }
      else {
         Write-Host "Not Azure Joined"
         $AADJoin = "ERROR"
         $AADDeviceID = "ERROR"
         $TenantId = "error"
      }
   }
   Catch {
      Write-Host "failed to gather AAD join information"
      $AADJoin = "ERROR"
      $AADDeviceID = "ERROR"
      $TenantId = "error"
      Throw "Get-AzureADDeviceInfo error discovered"
   }


   $AADTenant = $joinInfo.TenantDisplayName
   $TenantId = $joinInfo.TenantId
   $AADDeviceID = $joinInfo.DeviceId

   $props = @{
      TenantId    = $joinInfo.TenantId
      AADTenant   = $joinInfo.TenantDisplayName
      AADDeviceID = $joinInfo.DeviceId
   }
   Return $props

}

Function Get-CustInventory {
    [cmdletbinding()]
    Param (
       [Parameter(Mandatory=$true)]
       [string]$NameSpace,

       [Parameter(Mandatory=$true)]
       [string]$NewClassName,

       [Parameter(Mandatory=$true)]
       [string[]]$RegistryKeyList,

       [Parameter()]
       [bool]$CombineKeys,

       [Parameter()]
       [bool]$UseKeyNameAsKey,

       [Parameter()]
       [hashtable]$PropertyConfig
    )
    Try {

       $PropertyList = New-CustClassPropertyList -RegistryKeyList $RegistryKeyList -UseKeyNameAsKey $UseKeyNameAsKey @PropertyConfig

       $NewClassObj = New-CustWMIClass -NameSpace $NameSpace -ClassName $NewClassName -PropertyList $PropertyList -RemoveExisting
       If ($CombineKeys) {
          $RegProperties = Get-CustRegistryProperties -RegistryKey $RegistryKeyList
          Set-CustWMIClass -NameSpace $NameSpace -ClassName $NewClassName -Values $RegProperties -PropertyList $PropertyList | Out-Null
       }
       Else {
          ForEach ($Key in $RegistryKeyList) {
             $RegKeys = Get-Item -Path $Key -ErrorAction SilentlyContinue
             ForEach ($RegKey in $RegKeys) {
                $RegProperties = Get-CustRegistryProperties -RegistryKey $RegKey
                $RegProperties["KeyName"] = $RegKey.PSChildName
                Set-CustWMIClass -NameSpace $NameSpace -ClassName $NewClassName -Values $RegProperties -PropertyList $PropertyList | Out-Null
             }
          }
       }
       Return $True
    }
    Catch {
       Return $_.Exception.Message
    }
 }

 Function New-CustClassPropertyList {
    [cmdletbinding()]
    Param (
       [string[]]$RegistryKeyList,
       [bool]$UseKeyNameAsKey,
       [string[]]$KeyProps,
       [string[]]$ExcludeProps,
       [string[]]$Uint32Props,
       [string[]]$Uint64Props,
       [string[]]$UInt8Props,
       [string[]]$UInt16Props,
       [string[]]$SInt8Props,
       [string[]]$SInt16Props,
       [string[]]$SInt32Props,
       [string[]]$SInt64Props,
       [string[]]$Real32Props,
       [string[]]$Real64Props,
       [string[]]$BooleanProps,
       [string[]]$DateTimeProps,
       [string[]]$Char16Props
    )

    Try {
        $Properties = ForEach($RegistryKey in $RegistryKeyList) {
            $RegKey = Get-Item -Path $RegistryKey -ErrorAction SilentlyContinue
            If($RegKey) {
                $RegKey.Property
            }
        }

        If ($Properties) {
            $Properties = $Properties | Select-Object -Unique $_

            [System.Collections.ArrayList]$ObjArray = ForEach ($Prop in $Properties) {
             If(!($Prop -in $ExcludeProps)) {
                $CIMQualifiers = If($Prop -in $KeyProps) {
                                  @("key","read")
                                }
                                Else {
                                  @("read")
                                }
                $CIMtype =
                        If($Prop -in $UInt8Props) {
                            [System.Management.CimType]::UInt8
                        }
                        ElseIf($Prop -in $UInt16Props) {
                            [System.Management.CimType]::UInt16
                        }
                        ElseIf($Prop -in $UInt32Props) {
                            [System.Management.CimType]::UInt32
                        }
                        ElseIf($Prop -in $UInt64Props) {
                            [System.Management.CimType]::UInt64
                        }
                        ElseIf($Prop -in $SInt8Props) {
                            [System.Management.CimType]::SInt8
                        }
                        ElseIf($Prop -in $SInt16Props) {
                            [System.Management.CimType]::SInt16
                        }
                        ElseIf($Prop -in $SInt32Props) {
                            [System.Management.CimType]::SInt32
                        }
                        ElseIf($Prop -in $SInt64Props) {
                            [System.Management.CimType]::SInt64
                        }
                        ElseIf($Prop -in $Real32Props) {
                            [System.Management.CimType]::Real32
                        }
                        ElseIf($Prop -in $Real64Props) {
                            [System.Management.CimType]::Real64
                        }
                        ElseIf($Prop -in $BooleanProps) {
                            [System.Management.CimType]::Boolean
                        }
                        ElseIf($Prop -in $DateTimeProps) {
                            [System.Management.CimType]::DateTime
                        }
                        ElseIf($Prop -in $Char16Props) {
                            [System.Management.CimType]::Char16
                        }
                        Else {
                            [System.Management.CimType]::String
                        }
                $Obj =  [PSCustomObject]@{
                    Name = $Prop
                    Type = $CIMType
                    Qualifiers = $CIMQualifiers
                }
                $Obj
            }
          }
        }

        If($UseKeyNameAsKey) {
          $Obj =  [PSCustomObject]@{
             Name = "KeyName"
             Type = [System.Management.CimType]::String
             Qualifiers = @("key","read")
          }

       }
        $ObjArray += ($Obj)
        Return $ObjArray
    }
    Catch {
       Throw $_
    }
 }

 Function Remove-CustWMIInstance {
    [cmdletbinding()]
    Param (
       [String]$Namespace,
       [String]$ClassName
    )
    Try {
     $ExistingClass = Get-CIMClass -Namespace $NameSpace -ClassName $ClassName -ErrorAction SilentlyContinue
       If ($ExistingClass) {
          ([wmiclass]"$($Namespace):$($ClassName)").Delete()
       }
    }
    Catch {
       Throw $_
    }
 }

 Function New-CustWMIClass {
    [cmdletbinding()]
    Param (
       [String]$NameSpace,
       [String]$ClassName,
       [object]$PropertyList,
       [Switch]$RemoveExisting
    )
    Try {
       If ($RemoveExisting.IsPresent) {
          Remove-CustWMIInstance -NameSpace $NameSpace -ClassName $ClassName
       }

       If (Get-CimClass -ClassName $ClassName -Namespace $NameSpace -ErrorAction SilentlyContinue) {
          Write-Verbose "WMI Class $($ClassName) Already Exists" | Out-Null
       }
       Else {
          Write-Verbose "Create WMI Class $($ClassName)" | Out-Null
          $NewClass = New-Object System.Management.ManagementClass($NameSpace, [String]::Empty, $Null);
          $NewClass['__CLASS'] = $ClassName
          $NewClass.Qualifiers.Add("Static", $true)

          ForEach ($Obj in $PropertyList) {
             $NewClass.Properties.Add($Obj.Name, $Obj.Type, $false)
             ForEach ($Qualifier in $Obj.Qualifiers) {
                $NewClass.Properties[$Obj.Name].Qualifiers.Add("$($Qualifier)", $true)
             }
          }
          $NewClass.Put() | Out-Null
       }
       Write-Verbose "End of trying to create an empty $($ClassName) to populate later" | Out-Null
       $NewClassObj = Get-CimClass -ClassName $ClassName -Namespace $NameSpace
       Return $NewClassObj
    }
    Catch {
       Throw $_
    }
 }

 Function Set-CustWMIClass {
    [cmdletbinding()]
    Param (
       [String]$NameSpace,
       [String]$ClassName,
       [System.Collections.Specialized.OrderedDictionary]$Values,
       $PropertyList
    )
    Try {
       $ValueList = @{}
       ForEach ($Obj in $PropertyList) {
          If ($Values[$Obj.Name]) {
             If($Obj.Type -eq [System.Management.CimType]::UInt8) {
                $ValueList[$Obj.Name] = ([byte]$Values[$Obj.Name])
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::UInt16) {
                $ValueList[$Obj.Name] = ([uint16]$Values[$Obj.Name])
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::UInt32) {
                $ValueList[$Obj.Name] = ([uint32]$Values[$Obj.Name])
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::UInt64) {
                $ValueList[$Obj.Name] = ([uint64]$Values[$Obj.Name])
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::SInt8) {
                $ValueList[$Obj.Name] = ([sbyte]$Values[$Obj.Name])
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::SInt16) {
                $ValueList[$Obj.Name] = ([int16]$Values[$Obj.Name])
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::SInt32) {
                $ValueList[$Obj.Name] = ([int]$Values[$Obj.Name])
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::SInt64) {
                $ValueList[$Obj.Name] = ([int64]$Values[$Obj.Name])
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::Real32) {
                $ValueList[$Obj.Name] = ([single]$Values[$Obj.Name])
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::Real64) {
                $ValueList[$Obj.Name] = ([double]$Values[$Obj.Name])
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::Boolean) {
                $ValueList[$Obj.Name] = ([bool]$Values[$Obj.Name])
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::DateTime) {
                $ValueList[$Obj.Name] = ([DateTime]$Obj.Name)
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::Char16) {
                $ValueList[$Obj.Name] = ([char]$Values[$Obj.Name])
             }
             ElseIf($Obj.Type -eq [System.Management.CimType]::String) {
                $ValueList[$Obj.Name] = ($Values[$Obj.Name])
             }
             Else {
                $ValueList[$Obj.Name] = ([string]$Values[$Obj.Name])
             }

          }
       }
       If($ValueList.Count -ge 1) {
         $NewInstance = New-CimInstance -Namespace $NameSpace -ClassName $ClassName -Arguments $ValueList -ErrorAction SilentlyContinue
       }
       Else {
         Throw "No registry entries found. Exiting."
       }
       If($NewInstance) {
         Return $NewInstance
      }
      Else {
         Throw "Failed to create new entry. Error: $($Error[0])"
      }
    }
    Catch {
       Throw $_
    }
 }
 Function Get-CustRegistryProperties {
    [cmdletbinding()]
    Param (
       $RegistryKey
    )
    Try {
       [System.Collections.Specialized.OrderedDictionary]$PropertyList = [ordered]@{}
       If ($RegistryKey -is [string[]]) {
          ForEach ($Key in $RegistryKey) {
             $RegKey = Get-Item -Path "$($Key)" -ErrorAction SilentlyContinue
             If ($RegKey) {
                ForEach ($Prop in $RegKey.Property) {
                   $PropertyList[$Prop] = Get-ItemPropertyValue -Path $Key -Name $Prop
                }
             }
          }
       }
       Else {
          ForEach ($Prop in $RegistryKey.Property) {
             $PropertyList[$Prop] = $RegistryKey | Get-ItemPropertyValue -Name $Prop -ErrorAction SilentlyContinue
          }
       }
       Return $PropertyList
    }
    Catch {
       Throw $_
    }
 }
 #endregion

 #region Main

 $AADInfo = Get-AzureADDeviceInfo

 Get-CustInventory @InvArgs
 #endregion
