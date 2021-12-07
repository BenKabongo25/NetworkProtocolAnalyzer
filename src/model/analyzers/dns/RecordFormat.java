package model.analyzers.dns;

public class RecordFormat {
    protected final String name;
    protected final Type type;
    protected final int typeCode;
    protected final Class class_;
    protected final int classCode;

    public RecordFormat(String name, int typeCode, int classCode) {
        this.name = name;
        this.typeCode = typeCode;
        Type type1 = Type.getType(typeCode);
        if (type1 == null)
            type1 = Type.UNRECOGNIZED_TYPE;
        type = type1;
        this.classCode = classCode;
        Class class1 = Class.getClass(classCode);
        if (class1 == null)
            class1 = Class.UNRECOGNIZED_CLASS;
        class_ = class1;
    }

    public String getName() {
        return name;
    }

    public Type getType() {
        return type;
    }

    public Class getClass_() {
        return class_;
    }

    public int getTypeCode() {
        return typeCode;
    }

    public int getClassCode() {
        return classCode;
    }

    @Override
    public String toString() {
        return name +
                " (class = " + class_.getName() + ((class_ == Class.UNRECOGNIZED_CLASS) ? " (" + classCode + ")" : ")") +
                ", type = " + type.getName() + ((type == Type.UNRECOGNIZED_TYPE) ? " (" + typeCode + ")" : ")");
    }
}
