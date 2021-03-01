/*
	Gootloader threat hunting yara rule
	Author: Gabor Szappanos, SophosLabs
	Date: 25 February 2021
	Reference: https://news.sophos.com/en-us/2021/03/01/gootloader-expands-its-payload-delivery-options
*/

rule Gootloader_JavaScript_infector
{
	strings:
		$a1 = /function .{4,60}{return .{1,20} % .{0,8}\(.{1,20}\+.{1,20}\);}/
		$a2 = /function [\w]{1,14}\(.{1,14},.{1,50}\) {return .{1,14}\.substr\(.{1,10},.{1,10}\);}/
		$a3 = /function [\w]{1,14}\(.{1,50}\) {return .{1,14}.{1,10}\.length;.{1,4}}/
		$a4 = /function [\w]{1,14}\(.{0,40}\){.{0,40};while \([\w]{1,20} < [23][\d]{3}\) {/
		$a5 = /;WScript\.Sleep\([\d]{4,10}\);/
	condition:
		all of ($a*)
}

