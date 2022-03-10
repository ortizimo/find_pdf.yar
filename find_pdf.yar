import "pe"

rule find_pdf
{
	meta:
		author = "Saulo 'Sal' Ortiz, Senior Cyber Forensics Analyst, ATG"
		description = "Simple rule to find .PDF documents"
		date = "2021-10-22"
		updated = "2022-01-28"
		
		note = "Files in $Recycle.Bin do not show their actual name. Look for the file's metadata file ($I...) for its actual name"

	strings:
		$magic = { 25 50 44 46 } private								
		$header = /%PDF-.\.(.)/
		$PDF = /.pdf/ fullword nocase private
		//$CreationDate = /CreationDate.D:[a-zA-Z0-9]{14}/ nocase		// when document was created not when it was received by system
	
	condition:
		($magic at 0) and $PDF and $header
}
