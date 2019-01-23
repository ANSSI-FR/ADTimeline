## Description:

The ADTimeline script generates a timeline based on Active Directory replication metadata for objects considered of interest.  
Replication metadata gives you the time at which each replicated attribute for a given object was last changed. As a result the timeline of modifications is partial. For each modification of a replicated attribute a version number is incremented.  
ADTimeline was presented at the [CoRI&IN 2019](https://www.cecyf.fr/activites/recherche-et-developpement/coriin-2019/) (Conférence sur la réponse aux incidents et l’investigation numérique). Slides of the presentation, in french language,  are available [here](https://www.ssi.gouv.fr/publication/investigation-numerique-sur-lannuaire-active-directory-avec-les-metadonnees-de-replication-outil-adtimeline/). 

Objects considered of interest retrieved by the script include:

- Schema and configuration partition root objects.
- Domain root and objects located directly under the root.
- Objects having an ACE on the domain root.
- Domain roots located in the AD forest.
- Domain trusts.
- Deleted users (i.e. tombstoned).
- Objects protected by the SDProp process (i.e. AdminCount equals 1).
- The AdminSDHolder object.
- Class Schema objects.
- Existing and deleted Group Policy objects.
- DPAPI secrets.
- Domain controllers (Computer objects, ntdsdsa and server objects).
- DNS zones and admins.
- Accounts with suspicious SIDHistory (scope is forest wide).
- Sites.
- Organizational Units.
- Objects with Kerberos delegation enabled.
- Extended rights.
- Schema attributes with particular SearchFlags (Do not audit or confidential).
- Kerberoastable user accounts (SPN value).
- AS-REP roastable accounts (UserAccountControl value).
- CertificationAuthority objects.
- Cross Reference containers.
- Exchange RBAC roles and accounts assigned to a role.
- Exchange mail flow configuration objects.
- Deleted objects under the configuration partition.
- Dynamic objects.
- The directory service and RID manager objects.
- The Pre Windows 2000 compatible access, Cert publishers, GPO creator owners and DNS Admins groups.
- Custom groups which have to be manually defined.

## Prerequisites:

- The account launching the script should be able to read objects in the tombstone (Deleted Objects Container) and some parts of the Exchange settings located in the configuration partition (View-Only Organization management). Delegation can be tricky to setup (especially for reading the tombstone). That is why we advise you to run the script with a domain admin account. If you launch the script as a standard user, it will process the timeline without the objects mentioned.
- Computer should run Windows NT 6.1 or later and have the Active Directory Powershell module installed (part of RSAT-AD-Tools).
- If you enabled PowerShell Constrained Language Mode the script might fail (calling $error.clear()). Consider whitelisting the script via your device guard policy.
- If you are using offline mode install the ADLDS role on your analysis machine in order to use dsamain.exe and mount the NTDS database.

## Usage:

In online mode no argument is mandatory and the closest global catalog is used for processing. If no global catalog is found run the script with the server argument :
```
PS> .\AD-timeline.ps1 -server <GLOBAL CATALOG FQDN>
```
In offline mode: Replay if necessary transaction logs of the NTDS database, mount it on your analysis machine (ADLDS + RSAT-AD-Tools installed) and use 3266 as LDAP port.
```
C:\Windows\System32> dsamain.exe -dbpath <NTDS.DIT path> -ldapport 3266 -allownonadminaccess
```
If necessary use the allowupgrade switch.

Launch the script targetting localhost on port 3266:
```
PS> .\AD-timeline.ps1 -server "127.0.0.1:3266"
```

## Files generated

Output files are generated in the current directory:

- timeline.csv: The timeline generated with the AD replication metadata of objects retrieved.
- log-adexport.log: Script log file. You will also find various information on the domain.
- ADobjects.xml: Objects of interest retrieved via LDAP.
- gcADobjects.xml: Objects of interest retrieved via the Global Catalog.


To import files for analysis with powershell.
```
PS> import-csv timeline.csv -delimiter ";"
PS> import-clixml ADobjects.xml
PS> import-clixml gcADobjects.xml
```

## Custom groups

If you want to include custom AD groups in the timeline (for example virtualization admin groups, network admins, VIP groups...) just uncomment and edit the following array at the  begining of the script:
```
$groupscustom = ("VIP-group1","ESX-Admis","Tier1-admins")
```

