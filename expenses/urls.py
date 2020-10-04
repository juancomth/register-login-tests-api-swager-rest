from django.urls import path
from .views import *

urlpatterns = [
    path('', ExpenseListAPIViews.as_view(), name='expenses'),
    path('<int:id>', ExpenseDetailAPIView.as_view(), name="expense")
]