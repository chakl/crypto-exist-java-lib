/**
 * eXist-db EXPath Cryptographic library
 * eXist-db wrapper for EXPath Cryptographic Java library
 * Copyright (C) 2016 Claudius Teodorescu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package org.expath.exist.crypto.digest;

/**
 * Implements the crypto:hash() function for eXist.
 *
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius Teodorescu</a>
 */

import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.BinaryValue;
import org.exist.xquery.value.FunctionParameterSequenceType;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.StringValue;
import org.exist.xquery.value.Type;
import org.expath.exist.crypto.EXpathCryptoException;

import ro.kuberam.libs.java.crypto.CryptoException;
import ro.kuberam.libs.java.crypto.digest.Hash;

import static org.exist.xquery.FunctionDSL.*;
import static org.expath.exist.crypto.ExistExpathCryptoModule.*;

public class HashFunction extends BasicFunction {

	private static final Logger LOG = LogManager.getLogger(HashFunction.class);

	private static final String FS_HASH_NAME = "hash";
	private static final FunctionParameterSequenceType FS_HASH_PARAM_DATA = param("data", Type.ANY_TYPE,
			"The data to be hashed.");
	private static final FunctionParameterSequenceType FS_HASH_PARAM_ALGORITHM = param("algorithm", Type.STRING,
			"The cryptographic hashing algorithm.");

	public static final FunctionSignature FS_HASH[] = functionSignatures(FS_HASH_NAME,
			"resulting hash value, as string.", returnsOptMany(Type.BYTE),
			arities(arity(FS_HASH_PARAM_DATA, FS_HASH_PARAM_ALGORITHM),
					arity(FS_HASH_PARAM_DATA, FS_HASH_PARAM_ALGORITHM, param("encoding", Type.STRING,
							"The encoding of the output. The legal values are \"hex\" and \"base64\". The default value is \"base64\"."))));

	public HashFunction(final XQueryContext context, final FunctionSignature signature) {
		super(context, signature);
	}

	@Override
	public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {

		final int inputType = args[0].itemAt(0).getType();
		final String hashAlgorithm = args[1].getStringValue();
		final String encoding = Optional.ofNullable(args[2].getStringValue()).filter(str -> !str.isEmpty())
				.orElse("base64");
		LOG.debug("encoding = {}", () -> encoding);

		final Sequence result;
		if (inputType == Type.STRING || inputType == Type.ELEMENT || inputType == Type.DOCUMENT) {
			try {
				result = new StringValue(Hash.hashString(args[0].getStringValue(), hashAlgorithm, encoding));
			} catch (CryptoException e) {
				throw new EXpathCryptoException(this, e.getCryptoError());
			}
		} else if (inputType == Type.BASE64_BINARY || inputType == Type.HEX_BINARY) {
			try {
				final BinaryValue binaryValue = (BinaryValue) args[0].itemAt(0);
				try (final InputStream is = binaryValue.getInputStream()) {
					result = new StringValue(Hash.hashBinary(is, hashAlgorithm, encoding));
				}
			} catch (CryptoException e) {
				throw new EXpathCryptoException(this, e.getCryptoError());
			} catch (IOException e) {
				throw new EXpathCryptoException(this, e);
			}
		} else {
			result = Sequence.EMPTY_SEQUENCE;
		}

		return result;
	}
}