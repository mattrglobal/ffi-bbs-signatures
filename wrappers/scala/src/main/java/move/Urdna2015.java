package move;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.ld.signature.LinkedDataSuiteError;
import com.apicatalog.ld.signature.LinkedDataSuiteError.Code;
import com.apicatalog.rdf.Rdf;
import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.io.RdfWriter;
import com.apicatalog.rdf.io.error.RdfWriterException;
import com.apicatalog.rdf.io.error.UnsupportedContentException;
import io.setl.rdf.normalization.RdfNormalize;
import jakarta.json.JsonStructure;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;

public class Urdna2015 {

    final JsonStructure document;

    public Urdna2015(JsonStructure document) {
        this.document = document;
    }

    public RdfDataset toNormalRdf() throws JsonLdError {

        RdfDataset dataset = JsonLd.toRdf(JsonDocument.of(document)).get();

        RdfDataset canonical = RdfNormalize.normalize(dataset);

        return canonical;
    }

    public byte[] canonicalize(RdfDataset normalRdf) throws LinkedDataSuiteError {
        try {

            StringWriter writer = new StringWriter();

            RdfWriter rdfWriter = Rdf.createWriter(MediaType.N_QUADS, writer);

            rdfWriter.write(normalRdf);


            return writer.toString()
                    .getBytes(StandardCharsets.UTF_8);

        } catch ( UnsupportedContentException | IOException | RdfWriterException e) {
            throw new LinkedDataSuiteError(Code.Canonicalization, e);
        }
    }
}
