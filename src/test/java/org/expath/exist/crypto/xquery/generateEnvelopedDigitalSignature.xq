(:
 : eXist-db EXPath Cryptographic library
 : eXist-db wrapper for EXPath Cryptographic Java library
 : Copyright (C) 2016 Claudius Teodorescu
 :
 : This library is free software; you can redistribute it and/or
 : modify it under the terms of the GNU Lesser General Public License
 : as published by the Free Software Foundation; either version 2.1
 : of the License, or (at your option) any later version.
 :
 : This library is distributed in the hope that it will be useful,
 : but WITHOUT ANY WARRANTY; without even the implied warranty of
 : MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 : GNU Lesser General Public License for more details.
 :
 : You should have received a copy of the GNU Lesser General Public License
 : along with this library; if not, write to the Free Software Foundation,
 : Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 :)
xquery version "3.0";

import module "http://expath.org/ns/crypto";

let $expected-result :=
	<expected-result>/KaCzo4Syrom78z3EQ5SbbB4sF7ey80etKII864WF64B81uRpH5t9jQTxeEu0ImbzRMqzVDZkVG9
	xD7nN1kuFw==
	</expected-result>
let $sample-doc := doc('../resources/doc-1.xml')
let $certificate-details :=
	<digital-certificate>
		<keystore-type>JKS</keystore-type>
		<keystore-password>ab987c</keystore-password>
		<key-alias>eXist</key-alias>
		<private-key-password>kpi135</private-key-password>
		<keystore-uri>{concat('xmldb:', resolve-uri('../resources/keystore.ks', concat(substring-after(system:get-module-load-path(), 'xmldb:'), '/')))}</keystore-uri>
	</digital-certificate>
let $actual-result :=
	<actual-result>
		{
		let $signed-doc := crypto:generate-signature($sample-doc, "inclusive", "SHA1", "DSA_SHA1", "dsig", "enveloped")
		return $signed-doc//*[local-name() = 'P']/text()
		}
	</actual-result>
let $condition := normalize-space($expected-result/text()) = normalize-space($actual-result/text())
	

return
	<result>
		{
		(
		if ($condition)
			then <result-token>passed</result-token>
			else <result-token>failed</result-token>
		, $actual-result
		)
		}
	</result>