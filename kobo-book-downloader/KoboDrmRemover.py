from Crypto.Cipher import AES
from Crypto.Util import Padding

from typing import Dict
import base64
import binascii
import hashlib
import zipfile

# Based on obok.py by Physisticated.
class KoboDrmRemover:
	def __init__( self, deviceId: str, userId: str ):
		self.DeviceIdUserIdKey = KoboDrmRemover.__MakeDeviceIdUserIdKey( deviceId, userId )

	@staticmethod
	def __MakeDeviceIdUserIdKey( deviceId: str, userId: str ) -> bytes:
		deviceIdUserId = ( deviceId + userId ).encode()
		key = hashlib.sha256( deviceIdUserId ).hexdigest()
		return binascii.a2b_hex( key[ 32: ] )

	def __DecryptContents( self, contents: bytes, contentKeyBase64: str ) -> bytes:
		contentKey = base64.b64decode( contentKeyBase64 )
		keyAes = AES.new( self.DeviceIdUserIdKey, AES.MODE_ECB )
		decryptedContentKey = keyAes.decrypt( contentKey )

		contentAes = AES.new( decryptedContentKey, AES.MODE_ECB )
		decryptedContents = contentAes.decrypt( contents )
		return Padding.unpad( decryptedContents, AES.block_size, "pkcs7" )

	def __TruncateFilename( self, filename: str, max_bytes: int = 65535 ) -> str:
		"""Truncate filename to fit within ZIP format limits."""
		filename_bytes = filename.encode( "utf-8" )
		if len( filename_bytes ) <= max_bytes:
			return filename
		
		# Truncate byte by byte, ensuring we don't break UTF-8 sequences
		truncated = filename_bytes[ :max_bytes ]
		while truncated:
			try:
				return truncated.decode( "utf-8" )
			except UnicodeDecodeError:
				# Remove last byte and try again
				truncated = truncated[ :-1 ]
		
		# Fallback if something goes wrong
		return filename[ :1000 ]

	def RemoveDrm( self, inputPath: str, outputPath: str, contentKeys: Dict[ str, str ] ) -> None:
		with zipfile.ZipFile( inputPath, "r" ) as inputZip:
			# Use allowZip64=True to support larger files and metadata
			with zipfile.ZipFile( outputPath, "w", zipfile.ZIP_DEFLATED, allowZip64=True ) as outputZip:
				for filename in inputZip.namelist():
					contents = inputZip.read( filename )
					contentKeyBase64 = contentKeys.get( filename, None )
					if contentKeyBase64 is not None:
						contents = self.__DecryptContents( contents, contentKeyBase64 )
					
					# Truncate filename to stay within ZIP format limits
					truncated_filename = self.__TruncateFilename( filename )
					
					# Get the ZipInfo and strip extra fields that might be too large
					zinfo = inputZip.getinfo( filename )
					zinfo.filename = truncated_filename
					zinfo.extra = b''  # Strip extra fields to avoid metadata overflow
					
					outputZip.writestr( zinfo, contents )
