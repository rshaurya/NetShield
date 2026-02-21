import streamlit as st
import sys
import os

root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

if root_path not in sys.path:
    sys.path.insert(0, root_path)

from backend.core.analyzer import analyze_url

st.set_page_config(
    page_title="NetShield | URL Safety", 
    layout="centered"
)

st.title("Test website demo")
st.subheader("Tiered Analysis URL Safety Checker")
st.markdown("Enter a link below.")

url_input = st.text_input("Enter a URL to analyze:", placeholder="http://suspicious-login-update.com")

if st.button("Analyze URL", type="primary"):
    if url_input: 
        with st.spinner("Running Tiered Analysis..."):
            try:
                result = analyze_url(url_input)
                
                st.divider()
                
                prediction = result.get("final_prediction")
                if prediction == "Safe":
                    st.success(f"**Verdict: {prediction}**")
                else:
                    st.error(f" **Verdict: {prediction}**")
                
                st.write("### Analysis Details")
                st.info(f"**Data Source:** {result.get('source')}")
                st.json(result) 
                
            except Exception as e:
                st.error(f"An error occurred while analyzing: {e}")
    else:
        st.warning("Please enter a URL first.")