package com.dvu.recon;

import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TutorHash extends AbstractMediator {

	private String tutorApiPastHrs;
	private String lastRunTime;
	private String apiSharedSecret;
	private String programGuid;

	public void setTutorApiPastHrs(String newValue) {
		tutorApiPastHrs = newValue;
	}

	public String getTutorApiPastHrs() {
		return tutorApiPastHrs;
	}

	public void setLastRunTime(String newValue) {
		lastRunTime = newValue;
	}

	public String getLastRunTime() {
		return lastRunTime;
	}

	public void setApiSharedSecret(String newValue) {
		apiSharedSecret = newValue;
	}

	public void setProgramGuid(String newValue) {
		programGuid = newValue;
	}

	private String generateHash(String query) {
		try {
			byte[] keyBytes = Base64.getDecoder().decode(apiSharedSecret);
			String algorithm = "HmacSHA1";
			Charset charset = Charset.forName("utf-8");
			SecretKeySpec signingKey = new SecretKeySpec(keyBytes, algorithm);
			Mac mac = Mac.getInstance(algorithm);
			mac.init(signingKey);

			return new String(Base64.getEncoder().encode(mac.doFinal(query.getBytes(charset))), charset);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			log.error("Error generating hash: " + e.getMessage(), e);
			return null;
		}
	}

	public boolean mediate(MessageContext context) {
		try {
			log.info("tutorApiPastHrs: " + tutorApiPastHrs);
			log.info("lastRunTime: " + lastRunTime);

			// Get current date
			Date currentDate = new Date();
			SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
			// Calculate start date
			Date startDate;
			if (lastRunTime != null && !lastRunTime.isEmpty()) {
				// Convert unix timestamp string to date
				//startDate = new Date(Long.parseLong(lastRunTime));
				startDate=dateFormat.parse(lastRunTime);
			} else {
				// Subtract past hours from current date
				int pastHrs = Integer.parseInt(tutorApiPastHrs);
				startDate = new Date(currentDate.getTime() - (pastHrs * 60 * 60 * 1000));
			}
			log.info("Parsed Date==>"+startDate);	
			// Format dates
			
			String formattedStartDate = dateFormat.format(startDate);
			String formattedEndDate = dateFormat.format(currentDate);
			String formattedNowDate = dateFormat.format(currentDate);

			// Set the formatted dates as properties
			context.setProperty("startDate", formattedStartDate);
			context.setProperty("endDate", formattedEndDate);
			context.setProperty("nowDate", formattedNowDate);

			// Generate query string
			String tutorQuery = "ProgramGuid=" + programGuid +
					"&StartDate=" + formattedStartDate +
					"&EndDate=" + formattedEndDate +
					"&Now=" + formattedNowDate;

			// Generate and set hash
			String hash = generateHash(tutorQuery);
			if (hash == null) {
				return false;
			}
			context.setProperty("hashstring", hash);
			context.setProperty("tutorQuery", tutorQuery);

			return true;
		} catch (Exception e) {
			log.error("Error in TutorHash mediator: " + e.getMessage(), e);
			return false;
		}
	}
}
