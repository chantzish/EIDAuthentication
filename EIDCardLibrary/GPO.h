/*	EID Authentication
    Copyright (C) 2009 Vincent Le Toux

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

enum GPOPolicy
{
  AllowSignatureOnlyKeys,
  AllowCertificatesWithNoEKU,
  AllowTimeInvalidCertificates,
  AllowIntegratedUnblock,
  ReverseSubject,
  X509HintsNeeded,
  IntegratedUnblockPromptString,
  CertPropEnabledString,
  CertPropRootEnabledString,
  RootsCleanupOption,
  FilterDuplicateCertificates,
  ForceReadingAllCertificates,
  scforceoption,
  scremoveoption,
} ;


DWORD GetPolicyValue(GPOPolicy Policy);
BOOL SetPolicyValue(GPOPolicy Policy, DWORD dwValue);