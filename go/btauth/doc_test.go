package btauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestExportedIdentifiersAreDocumented: every exported function, method on an
// exported type, type, constant, variable and struct field of the published
// packages has a doc comment (P5: no undocumented public items in godoc).
func TestExportedIdentifiersAreDocumented(t *testing.T) {
	for _, dir := range []string{".", "redisstore", "../sidecar"} {
		fset := token.NewFileSet()
		notTest := func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }
		pkgs, err := parser.ParseDir(fset, dir, notTest, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range pkgs {
			for _, f := range p.Files {
				for _, d := range f.Decls {
					for _, missing := range undocumented(d) {
						t.Errorf("%s: %s has no doc comment", fset.Position(missing.Pos()), missing.Name)
					}
				}
			}
		}
	}
}

func undocumented(d ast.Decl) []*ast.Ident {
	var out []*ast.Ident
	switch d := d.(type) {
	case *ast.FuncDecl:
		if d.Name.IsExported() && d.Doc == nil && (d.Recv == nil || exportedRecv(d.Recv)) {
			out = append(out, d.Name)
		}
	case *ast.GenDecl:
		for _, s := range d.Specs {
			switch s := s.(type) {
			case *ast.TypeSpec:
				if !s.Name.IsExported() {
					continue
				}
				if s.Doc == nil && d.Doc == nil {
					out = append(out, s.Name)
				}
				if st, ok := s.Type.(*ast.StructType); ok {
					for _, fl := range st.Fields.List {
						for _, n := range fl.Names {
							if n.IsExported() && fl.Doc == nil && fl.Comment == nil {
								out = append(out, n)
							}
						}
					}
				}
			case *ast.ValueSpec:
				for _, n := range s.Names {
					if n.IsExported() && s.Doc == nil && d.Doc == nil && s.Comment == nil {
						out = append(out, n)
					}
				}
			}
		}
	}
	return out
}

func exportedRecv(r *ast.FieldList) bool {
	t := r.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	id, ok := t.(*ast.Ident)
	return !ok || id.IsExported()
}
