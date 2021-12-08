package model.analyzers.dns;

import model.address.AddressIPv4;
import model.address.AddressIPv6;
import model.analyzers.AnalyzerException;
import model.analyzers.SimpleAnalyzer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DNSAnalyzer extends SimpleAnalyzer {

    private int pos;

    private int identification;
    private int QR;
    private OpCode opCode;
    private int authoritativeAnswer;
    private int truncated;
    private int recursionDesired;
    private int recursionAvailable;
    private int reserved;
    private int authenticatedData;
    private int checkingDisabled;
    private RCode rCode;
    private int nbQuestion;
    private int nbAnswer;
    private int nbAuthority;
    private int nbAdditional;
    private List<QuestionRecordFormat> questions;
    private List<AnswerRecordFormat> answers;
    private List<AnswerRecordFormat> authorities;
    private List<AnswerRecordFormat> additionals;

    public DNSAnalyzer(String[] t) {
        super("Domain Name System", "DNS", t);
    }

    public DNSAnalyzer(String t) {
        super("Domain Name System", "DNS", t);
    }

    private String findName() {
        if(Integer.parseInt(t[pos], 16) == 0) {
            pos++;
            return "<Root>";
        }
        String name = "";
        int constVal = Integer.parseInt("C000", 16);
        while (Integer.parseInt(t[pos], 16) != 0) {
            int v = Integer.parseInt(t[pos]+"00", 16);
            if (v < constVal) { // not compressed
                int l = pos +1 + Integer.parseInt(t[pos], 16);
                for (pos++; pos < l; pos++) {
                    name += Character.toString((char)Integer.parseInt(t[pos], 16));
                }
                if (Integer.parseInt(t[pos], 16) != 0)
                    name += ".";
                else {
                    pos++;
                    return name;
                }
            }
            else {  // compressed message
                int p2 = Integer.parseInt(t[pos]+t[pos +1], 16) - constVal;
                int pavant = pos;
                pos = 0;
                name += findNameRec(p2);
                if(pos == 1) {
                    pos = pavant+2;
                    return name;
                }
                pos = pavant + 2;
            }
        }

        return name;
    }

    private String findNameRec(int p) {
        String name = "";
        int constVal = Integer.parseInt("C000", 16);
        while (Integer.parseInt(t[p], 16) != 0) {
            if (pos == 1) return name;
            int v = Integer.parseInt(t[p] + "00", 16);
            if (v < constVal) { // not compressed
                int l = p + 1 + Integer.parseInt(t[p], 16);
                for (p++; p < l; p++) {
                    name += Character.toString((char) Integer.parseInt(t[p], 16));
                }
                if (Integer.parseInt(t[p], 16) != 0)
                    name += ".";
                else {
                    p++;
                    pos = 1;
                    return name;
                }
            } else {  // compressed message
                int p2 = Integer.parseInt(t[p] + t[p + 1], 16) - constVal;
                name += findNameRec(p2);
                p += 2;
            }
        }

        return name;
    }

    private void findAnswersRecords(String title, int nb, List<AnswerRecordFormat> list) throws AnalyzerException {
        for(int i = 0; i < nb; i++) {
            String name = findName();
            int type = Integer.parseInt(t[pos]+t[pos +1], 16);
            int class_ = Integer.parseInt(t[pos +2]+t[pos +3], 16);
            long TTL = Long.parseLong(t[pos +4]+t[pos +5]+ t[pos +6]+t[pos +7], 16);
            int length = Integer.parseInt(t[pos +8]+t[pos +9], 16);

            String data = "";
            if (type == Type.A.getValue()) {
                AddressIPv4 ip = new AddressIPv4(
                        Integer.parseInt(t[pos +10], 16),
                        Integer.parseInt(t[pos +11], 16),
                        Integer.parseInt(t[pos +12], 16),
                        Integer.parseInt(t[pos +13], 16));
                data += ip.toString();
            }
            else if (type == Type.AAAA.getValue()) {
                AddressIPv6 ip = new AddressIPv6(
                  t[pos+10]+t[pos+11],
                  t[pos+12]+t[pos+13],
                  t[pos+14]+t[pos+15],
                  t[pos+16]+t[pos+17],
                  t[pos+18]+t[pos+19],
                  t[pos+20]+t[pos+21],
                  t[pos+22]+t[pos+23],
                  t[pos+24]+t[pos+25]
                );
                data += ip;
            }
            else if (type == Type.CNAME.getValue() || type == Type.NS.getValue() || type == Type.MX.getValue())
                data += findName();
            else
                data = "0x" + String.join("", Arrays.copyOfRange(t, pos+10, pos+10+length));

            list.add(new AnswerRecordFormat(name,type, class_, TTL, length, data));

            pos += 10+length;
        }
    }

    @Override
    public void analyze() throws AnalyzerException {
        identification = Integer.parseInt(t[0]+t[1],16);
        informations.put("Transaction Identifier", new String[]{String.valueOf(identification), "0x"+t[0]+t[1]});

        String flags = Integer.toBinaryString(Integer.parseInt(t[2] + t[3], 16));
        if (flags.length() < 16)
            flags = "0000000000000000".substring(0, 16-flags.length()) + flags;

        QR = Integer.parseInt(flags.substring(0, 1), 2);
        informations.put("Question Response (QR)", new String[]{String.valueOf(QR), (QR == 0) ? "Request": "Response"});

        int code = Integer.parseInt(flags.substring(1, 5), 2);
        opCode = OpCode.getOpCode(code);
        if (opCode == null)
            opCode = OpCode.UNRECONGIZED_CODE;
        informations.put("Operation code", new String[]{opCode.toString(), opCode.getDescription()});

        authoritativeAnswer = Integer.parseInt(flags.substring(5, 6), 2);
        informations.put("Authoritative Answer (AA)", new String[]{String.valueOf(authoritativeAnswer), (authoritativeAnswer == 0) ? "Cache":"Authoritative"});
        truncated = Integer.parseInt(flags.substring(6, 7), 2);
        informations.put("Truncated (TC)", new String[]{String.valueOf(truncated), (truncated == 0) ? "No":"Yes"});
        recursionDesired = Integer.parseInt(flags.substring(7, 8), 2);
        informations.put("Recursion Desired (RD)", new String[]{String.valueOf(recursionDesired), (recursionDesired == 0) ? "No":"Yes"});
        recursionAvailable = Integer.parseInt(flags.substring(8, 9), 2);
        informations.put("Recursion Available", new String[]{String.valueOf(recursionAvailable), (recursionAvailable == 0) ? "No":"Yes"});
        reserved = Integer.parseInt(flags.substring(9, 10), 2);
        informations.put("Reserved (Z)", new String[]{String.valueOf(reserved), ""});
        authenticatedData = Integer.parseInt(flags.substring(10, 11), 2);
        informations.put("Authenticated Data (AD)", new String[]{String.valueOf(authenticatedData), (authenticatedData == 0) ? "No":"Yes"});
        checkingDisabled = Integer.parseInt(flags.substring(11, 12), 2);
        informations.put("Checking Disabled (CD)", new String[]{String.valueOf(checkingDisabled), (checkingDisabled == 0) ? "No":"Yes"});

        int rc = Integer.parseInt(flags.substring(12), 2);
        rCode = RCode.getRCode(rc);
        if (rCode == null)
            rCode = RCode.UNRECOGNIZED_CODE;
        informations.put("R Code", new String[]{rCode.toString(), "0x"+flags.substring(12)});

        nbQuestion = Integer.parseInt(t[4]+t[5],16);
        nbAnswer = Integer.parseInt(t[6]+t[7],16);
        nbAuthority = Integer.parseInt(t[8]+t[9],16);
        nbAdditional = Integer.parseInt(t[10]+t[11],16);

        informations.put("Questions", new String[]{String.valueOf(nbQuestion), "0x"+t[4]+t[5]});
        informations.put("Answer RR", new String[]{String.valueOf(nbAnswer), "0x"+t[6]+t[7]});
        informations.put("Authority RR", new String[]{String.valueOf(nbAuthority), "0x"+t[8]+t[9]});
        informations.put("Additional RR", new String[]{String.valueOf(nbAdditional), "0x"+t[10]+t[11]});

        pos = 12;
        questions = new ArrayList<>();
        for(int i = 0; i < nbQuestion; i++) {
            String name = findName();
            int type = Integer.parseInt(t[pos] + t[pos +1], 16);
            int class_ = Integer.parseInt(t[pos +2] + t[pos +3], 16);
            questions.add(new QuestionRecordFormat(name, type, class_));
            pos += 4;
        }

        answers = new ArrayList<>();
        findAnswersRecords("Answer", nbAnswer, answers);

        authorities = new ArrayList<>();
        findAnswersRecords("Authority", nbAuthority, authorities);

        additionals = new ArrayList<>();
        findAnswersRecords("Additional", nbAdditional, additionals);
    }

    public int getIdentification() {
        return identification;
    }

    public int getQR() {
        return QR;
    }

    public OpCode getOpCode() {
        return opCode;
    }

    public int getAuthoritativeAnswer() {
        return authoritativeAnswer;
    }

    public int getTruncated() {
        return truncated;
    }

    public int getRecursionDesired() {
        return recursionDesired;
    }

    public int getRecursionAvailable() {
        return recursionAvailable;
    }

    public int getReserved() {
        return reserved;
    }

    public int getAuthenticatedData() {
        return authenticatedData;
    }

    public int getCheckingDisabled() {
        return checkingDisabled;
    }

    public RCode getrCode() {
        return rCode;
    }

    public int getNbQuestion() {
        return nbQuestion;
    }

    public int getNbAnswer() {
        return nbAnswer;
    }

    public int getNbAuthority() {
        return nbAuthority;
    }

    public int getNbAdditional() {
        return nbAdditional;
    }

    public List<QuestionRecordFormat> getQuestions() {
        return questions;
    }

    public List<AnswerRecordFormat> getAnswers() {
        return answers;
    }

    public List<AnswerRecordFormat> getAuthorities() {
        return authorities;
    }

    public List<AnswerRecordFormat> getAdditionals() {
        return additionals;
    }

    @Override
    public String getRecap() {
        return super.getRecap() + " (" + opCode + "), " + t.length + " bytes";
    }

    @Override
    public String toString() {
        String s = super.toString();
        if (!questions.isEmpty()) {
            s += "\nQuestions \n-------------------";
            for (QuestionRecordFormat question: questions) {
                s += "\n\t" + question.toString() +
                        "\n\t\tName = " + question.getName() +
                        "\n\t\tType = " + question.getType() +
                        "\n\t\tClass = " + question.getClass_();
            }
        }
        if (!answers.isEmpty()) {
            s += "\nAnswers \n-------------------";
            for (AnswerRecordFormat answer: answers) {
                s += "\n\t" + answer.toString() +
                        "\n\t\tName = " + answer.getName() +
                        "\n\t\tType = " + answer.getType() +
                        "\n\t\tClass = " + answer.getClass_() +
                        "\n\t\tTime to live = " + answer.getTTL() +
                        "\n\t\tData length = " + answer.getDataLength() +
                        "\n\t\tData = " + answer.getData();
            }
        }
        if (!authorities.isEmpty()) {
            s += "\nAuthority \n-------------------";
            for (AnswerRecordFormat answer: authorities) {
                s += "\n\t" + answer.toString() +
                        "\n\t\tName = " + answer.getName() +
                        "\n\t\tType = " + answer.getType() +
                        "\n\t\tClass = " + answer.getClass_() +
                        "\n\t\tTime to live = " + answer.getTTL() +
                        "\n\t\tData length = " + answer.getDataLength() +
                        "\n\t\tData = " + answer.getData();
            }
        }
        if (!additionals.isEmpty()) {
            s += "\nAdditional \n-------------------";
            for (AnswerRecordFormat answer: additionals) {
                s += "\n\t" + answer.toString() +
                        "\n\t\tName = " + answer.getName() +
                        "\n\t\tType = " + answer.getType() +
                        "\n\t\tClass = " + answer.getClass_() +
                        "\n\t\tTime to live = " + answer.getTTL() +
                        "\n\t\tData length = " + answer.getDataLength() +
                        "\n\t\tData = " + answer.getData();
            }
        }
        return s;
    }
}