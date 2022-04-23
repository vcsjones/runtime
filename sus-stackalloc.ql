import csharp

predicate isConstExpr(Expr e) {
    e instanceof MemberConstantAccess or
    e instanceof Literal or
    e instanceof SizeofExpr or
    (isConstExpr(e.(BinaryArithmeticOperation).getLeftOperand()) and isConstExpr(e.(BinaryArithmeticOperation).getRightOperand())) or
    (isConstExpr(e.(ConditionalExpr).getThen()) and isConstExpr(e.(ConditionalExpr).getElse())) or
    e.(VariableAccess).getTarget() instanceof LocalConstant or
    e.(VariableAccess).getTarget().(Field).isReadOnly() and isConstExpr(e.(VariableAccess).getTarget().getInitializer())
}

from Stackalloc sa
where
    not isConstExpr(sa.getALengthArgument+())
select
    sa,
    sa.getALocation().getFile().getBaseName() + ":" + sa.getALocation().getStartLine()

