package tasks

import "testing"

func TestNameVersionFromURL(t *testing.T) {
	for _, c := range []struct{ path, query, name, ver string }{
		{"/ajax/libs/jquery/3.6.0/jquery.min.js", "", "jquery", "3.6.0"},
		{"/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js", "", "bootstrap.bundle", "5.3.2"},
		{"/static/jquery-3.6.0.min.js", "", "jquery", "3.6.0"},
		{"/assets/app.js", "v=1.2.3", "app", "1.2.3"},
		{"/static/app.a1b2c3d4.js", "", "app.a1b2c3d4", ""},
		{"/css/site.css", "", "site", ""},
	} {
		n, v := nameVersion(c.path, c.query)
		if n != c.name || v != c.ver {
			t.Errorf("%s?%s -> (%q,%q), want (%q,%q)",
				c.path, c.query, n, v, c.name, c.ver)
		}
	}
}
