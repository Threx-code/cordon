#include <R.h>

void fold(double *x, int *n, double *out) {
  double total = 0;
  for (int i = 0; i < *n; i++) total += x[i];
  *out = total;
}
