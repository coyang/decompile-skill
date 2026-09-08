#include "cpp_shapes.h"

#include <string>
#include <vector>

const char *Shape::kind() const { return "shape"; }

Shape::~Shape() {}

namespace {

double clamp_unit(double v) {
  if (v < 0.0) {
    return 0.0;
  }
  if (v > 1.0) {
    return 1.0;
  }
  return v;
}

}  // namespace

double total_area(const std::vector<Shape *> &shapes) {
  double sum = 0.0;
  for (size_t i = 0; i < shapes.size(); ++i) {
    sum += clamp_unit(shapes[i]->area() / 100.0) * 100.0;
  }
  return sum;
}

std::string describe(const std::string &prefix, const std::vector<int> &nums) {
  std::string out = prefix;
  out += "[";
  for (size_t i = 0; i < nums.size(); ++i) {
    if (i > 0) {
      out += ",";
    }
    out += std::to_string(nums[i]);
  }
  out += "]";
  return out;
}

const char *shape_kind(const Shape *s) { return s->kind(); }

Rectangle *make_rect(double w, double h) { return new Rectangle(w, h); }

Circle *make_circle(double r) { return new Circle(r); }

double rect_perimeter(const Rectangle *r) { return r->perimeter(); }
