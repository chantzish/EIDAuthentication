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

//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) 2006 Microsoft Corporation. All rights reserved.
//
// This file contains some global variables that describe what our
// sample tile looks like.  For example, it defines what fields a tile has 
// and which fields show in which states of LogonUI.

#pragma once
#include <credentialprovider.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>

#define MAX_ULONG  ((ULONG)(-1))

// The indexes of each of the fields in our credential provider's tiles.
enum SAMPLE_FIELD_ID 
{
    SFI_TILEIMAGE       = 0,
    SFI_USERNAME        = 1,
	SFI_MESSAGE         = 2,
    SFI_PIN		        = 3,
    SFI_CERTIFICATE		= 4,
	SFI_SUBMIT_BUTTON   = 5, 
    SFI_NUM_FIELDS      = 6,  // Note: if new fields are added, keep NUM_FIELDS last.  This is used as a count of the number of fields
};

// Same as SAMPLE_FIELD_ID above, but for the CMessageCredential.
enum SAMPLE_MESSAGE_FIELD_ID 
{
    SMFI_TILEIMAGE		= 0,
	SMFI_MESSAGE        = 1, 
	SMFI_CANCELFORCEPOLICY	= 2,
    SMFI_NUM_FIELDS     = 3,  // Note: if new fields are added, keep NUM_FIELDS last.  This is used as a count of the number of fields
};

// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// These two arrays are seperate because a credential provider might
// want to set up a credential with various combinations of field state pairs 
// and field descriptors.

// The field state value indicates whether the field is displayed
// in the selected tile, the deselected tile, or both.
// The Field interactive state indicates when 
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] = 
{
    { CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SFI_TILEIMAGE
    { CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SFI_USERNAME
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SFI_MESSAGE
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },       // SFI_PIN
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },       // SFI_SUBMIT_BUTTON   
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },       // SFI_CERTIFICATE
};

// Same as s_rgFieldStatePairs above, but for the CMessageCredential.
static const FIELD_STATE_PAIR s_rgMessageFieldStatePairs[] = 
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SMFI_TILEIMAGE
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SMFI_MESSAGE
	{ CPFS_HIDDEN, CPFIS_NONE },          // SMFI_CANCELFORCEPOLICY
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { SFI_TILEIMAGE, CPFT_TILE_IMAGE ,L""},
    { SFI_USERNAME, CPFT_LARGE_TEXT,L""},
	{ SFI_MESSAGE, CPFT_SMALL_TEXT,L""},
    { SFI_PIN, CPFT_PASSWORD_TEXT,L""},
	{ SFI_CERTIFICATE, CPFT_COMMAND_LINK,L""},
    { SFI_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L""},
	
};

// Same as s_rgCredProvFieldDescriptors above, but for the CMessageCredential.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgMessageCredProvFieldDescriptors[] =
{
    { SMFI_TILEIMAGE, CPFT_TILE_IMAGE, L""},
	{ SMFI_MESSAGE, CPFT_LARGE_TEXT, L""},
	{ SMFI_CANCELFORCEPOLICY, CPFT_COMMAND_LINK, L"" },
};