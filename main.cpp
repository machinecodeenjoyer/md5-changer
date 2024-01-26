#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <random>

bool ReturnErrorMessage( const std::string& message );

std::string CalculateMD5( const std::string& filepath ) {
	std::ifstream File( filepath, std::ios::binary );
	if ( !File.is_open( ) ) {
		return "";
	}

	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	if ( !CryptAcquireContext( &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT ) ||
		!CryptCreateHash( hProv, CALG_MD5, 0, 0, &hHash ) ) {
		return "";
	}

	const int bufferSize = 4096;
	std::vector<BYTE> buffer( bufferSize );
	DWORD bytesRead = 0;

	while ( File.read( reinterpret_cast< char* >( buffer.data( ) ), buffer.size( ) ) && File.gcount( ) > 0 ) {
		bytesRead = static_cast< DWORD >( File.gcount( ) );

		if ( !CryptHashData( hHash, buffer.data( ), bytesRead, 0 ) ) {
			CryptDestroyHash( hHash );
			CryptReleaseContext( hProv, 0 );
			return "";
		}
	}

	BYTE hash[ 16 ];
	DWORD hashSize = 16;

	if ( !CryptGetHashParam( hHash, HP_HASHVAL, hash, &hashSize, 0 ) ) {
		CryptDestroyHash( hHash );
		CryptReleaseContext( hProv, 0 );
		return "";
	}

	CryptDestroyHash( hHash );
	CryptReleaseContext( hProv, 0 );

	std::stringstream ss;

	for ( int i = 0; i < hashSize; ++i ) {
		ss << std::hex << std::setw( 2 ) << std::setfill( '0' ) << static_cast< int >( hash[ i ] );
	}

	return ss.str( );
}

std::vector<char> GeneratePattern( ){
	std::vector<char> pattern;

	for ( char ch = 'A'; ch <= 'D'; ++ch ) {
		pattern.push_back( ch );
	}

	return pattern;
}

std::string GetExecutableDirectory( ) {
    char currentPath[ MAX_PATH ];
    if ( GetModuleFileName( NULL, currentPath, MAX_PATH ) == 0 ) {
        ReturnErrorMessage( "Unable to retrieve current module file name" );
        return "";
    }

    std::string fullPath = currentPath;
    size_t lastSlashPos = fullPath.find_last_of( "\\" );

    if ( lastSlashPos != std::string::npos ) {
        return fullPath.substr( 0, lastSlashPos + 1 );
    }
    else {
        ReturnErrorMessage( "Unable to extract directory from the current path" );
        return "";
    }
}

bool ChangeMD5Hash( ) {
    std::string ExecutableDirectory = GetExecutableDirectory( );
    if ( ExecutableDirectory.empty( ) ) {
        return false;
    }

    char CurrentPath[ MAX_PATH ];
    if ( GetModuleFileName( NULL, CurrentPath, MAX_PATH ) == 0 ) {
        ReturnErrorMessage( "Unable to retrieve current module file name" );
    }

    std::string OriginalFile = CurrentPath;
    std::string ModifiedFile = ExecutableDirectory + "modified_md5.exe";

    std::ifstream File( OriginalFile, std::ios::binary );
    if ( !File.is_open( ) ) {
        ReturnErrorMessage( "Unable to open the original file for reading" );
    }

    std::string OriginalHash = CalculateMD5( OriginalFile );
    if ( OriginalHash.empty( ) ) {
        ReturnErrorMessage( "Unable to calculate the MD5 hash of the original file" );
    }

    std::cout << "Original MD5 Hash: " << OriginalHash << std::endl;

    std::vector<char> FileData( ( std::istreambuf_iterator<char>( File ) ), std::istreambuf_iterator<char>( ) );

    PIMAGE_DOS_HEADER DosHeader = reinterpret_cast< PIMAGE_DOS_HEADER >( FileData.data( ) );
    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        ReturnErrorMessage( "Invalid DOS header signature" );
    }

    PIMAGE_NT_HEADERS NtHeader = reinterpret_cast< PIMAGE_NT_HEADERS >( &FileData[ DosHeader->e_lfanew ] );
    if ( NtHeader->Signature != IMAGE_NT_SIGNATURE ) {
        ReturnErrorMessage( "Invalid NT header signature" );
    }

    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION( NtHeader );
    PIMAGE_SECTION_HEADER CodeSection = nullptr;
    for ( int i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i ) {
        if ( strcmp( reinterpret_cast< char* >( SectionHeader[ i ].Name ), ".text" ) == 0 ) {
            CodeSection = &SectionHeader[ i ];
            break;
        }
    }

    if ( !CodeSection ) {
        ReturnErrorMessage( "Unable to locate the code section in the executable file" );
    }

    std::vector<char> PatternToFind = GeneratePattern( );

    if ( CodeSection->PointerToRawData >= FileData.size( ) ) {
        ReturnErrorMessage( "Invalid code section offset" );
    }

    auto CodeStart = FileData.begin( ) + CodeSection->PointerToRawData;
    auto CodeEnd = CodeStart + CodeSection->SizeOfRawData;

    if ( CodeEnd > FileData.end( ) ) {
        ReturnErrorMessage( "Invalid code section size" );
    }

    std::vector<char>::iterator It = std::search( CodeStart, CodeEnd, PatternToFind.begin( ), PatternToFind.end( ) );

    std::streamoff Offset = std::distance( FileData.begin( ), It );

    FileData[ Offset ] = 0x12;

    std::ofstream OutFile( ModifiedFile, std::ios::binary );
    if ( !OutFile.is_open( ) ) {
        ReturnErrorMessage( "Unable to open the modified file for writing" );
    }

    OutFile.write( FileData.data( ), FileData.size( ) );
    OutFile.close( );

    std::string ModifiedHash = CalculateMD5( ModifiedFile );
    if ( !ModifiedHash.empty( ) ) {
        std::cout << "Modified MD5 Hash: " << ModifiedHash << std::endl;
    }
    else {
        ReturnErrorMessage( "Unable to calculate the MD5 hash of the modified file" );
    }

    return true;
}

int main() {
	if ( !ChangeMD5Hash( ) ) {
		std::cout << "Failed to change MD5 hash" << std::endl;
	}

	return 0;
}

inline bool ReturnErrorMessage( const std::string& message ) {
	std::cerr << "Error: " << message << std::endl;
	return false;
}