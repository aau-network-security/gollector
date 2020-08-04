package extract_features

import (
	"database/sql"
	"unicode/utf8"

	"gopkg.in/vmarkovtsev/go-lcss.v1"
)

type IntStats struct {
	min, max, sum sql.NullInt64
	values        []int64
}

func (s *IntStats) Add(val int) {
	v := int64(val)
	s.values = append(s.values, v)

	// update max
	if !s.max.Valid || v > s.max.Int64 {
		s.max.Int64 = v
		s.max.Valid = true
	}

	// update min
	if !s.min.Valid || v < s.min.Int64 {
		s.min.Int64 = v
		s.min.Valid = true
	}

	// update sum
	s.sum.Valid = true
	s.sum.Int64 += v
}

func (s *IntStats) Min() sql.NullInt64 {
	return s.min
}

func (s *IntStats) Max() sql.NullInt64 {
	return s.max
}

func (s *IntStats) Mean() sql.NullFloat64 {
	if len(s.values) == 0 {
		return sql.NullFloat64{
			Valid: false,
		}
	}

	return sql.NullFloat64{
		Valid:   true,
		Float64: float64(s.sum.Int64) / float64(len(s.values)),
	}
}

func NewIntStats() IntStats {
	return IntStats{
		values: []int64{},
		min:    sql.NullInt64{},
		max:    sql.NullInt64{},
		sum:    sql.NullInt64{},
	}
}

type StringStats struct {
	values   []string
	computed bool

	uniques []string
}

func (s *StringStats) compute() {
	umap := make(map[string]bool)
	for _, v := range s.values {
		umap[v] = true
	}

	s.uniques = []string{}
	for k := range umap {
		s.uniques = append(s.uniques, k)
	}

	s.computed = true
}

func (s *StringStats) Add(val string) {
	s.computed = false
	s.values = append(s.values, val)
}

func (s *StringStats) Uniques() []string {
	if !s.computed {
		s.compute()
	}
	return s.uniques
}

func (s *StringStats) UniqueLen() int {
	return len(s.Uniques())
}

func NewStringStats() StringStats {
	return StringStats{
		values: []string{},
	}
}

type LcsStats struct {
	values   [][]byte
	computed bool
	longest  int

	str        string
	len        sql.NullInt64
	normalized sql.NullFloat64
}

func (s *LcsStats) compute() {
	lcs := lcss.LongestCommonSubstring(s.values...)
	runecount := utf8.RuneCount(lcs)

	s.str = string(lcs)
	s.len = sql.NullInt64{
		Int64: int64(runecount),
		Valid: true,
	}
	s.normalized = sql.NullFloat64{
		Float64: float64(runecount) / float64(s.longest),
		Valid:   true,
	}

	s.computed = true
}

func (s *LcsStats) Add(val string) {
	s.values = append(s.values, []byte(val))
	if len(val) > s.longest {
		s.longest = len(val)
	}
	s.computed = false
}

func (s *LcsStats) String() string {
	if !s.computed {
		s.compute()
	}
	return s.str
}

func (s *LcsStats) Len() sql.NullInt64 {
	if !s.computed {
		s.compute()
	}
	return s.len
}

func (s *LcsStats) Normalized() sql.NullFloat64 {
	if !s.computed {
		s.compute()
	}
	return s.normalized
}

func NewLcsStats() LcsStats {
	return LcsStats{
		values:     [][]byte{},
		computed:   false,
		longest:    0,
		str:        "",
		len:        sql.NullInt64{},
		normalized: sql.NullFloat64{},
	}
}
